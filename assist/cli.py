"""The Assist command line."""

import argparse
import json
import sys

from . import __version__, config, context as contextmod, media, session, tickets
from .llm import ModelError
from .media import MediaError
from .privacy import EgressBlocked
from .tickets import TicketError


def _emit(payload):
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def cmd_new(args):
    body = args.body or ""
    if args.body_file:
        with open(args.body_file, "r") as handle:
            body = handle.read()
    ticket = tickets.create(args.title, body)
    if not args.no_context:
        sys.stderr.write("gathering what this machine knows...\n")
        ticket.set_context(contextmod.gather(
            on_progress=lambda name, what: sys.stderr.write("  %s\n" % what)))
    for path in args.attach or []:
        session.attach(ticket, path)
    if args.json:
        _emit(ticket.summary())
        return 0
    sys.stdout.write("ticket %s\n" % ticket.id)
    sys.stdout.write("  %s\n" % ticket.directory)
    if args.ask:
        return _answer(ticket, None, args)
    sys.stdout.write("\nnow:  toolbox assist ask %s \"what should I check first?\"\n"
                     % ticket.id)
    return 0


def cmd_ask(args):
    ticket = tickets.load(args.ticket)
    return _answer(ticket, " ".join(args.question) or None, args)


def _answer(ticket, question, args):
    settings = config.load()
    streaming = not args.json
    if not args.json:
        model, vision = session.pick_model(ticket, settings)
        sys.stderr.write("asking %s%s on %s\n\n"
                         % (model, " (vision)" if vision else "", settings["endpoint"]))

    def on_token(piece):
        sys.stdout.write(piece)
        sys.stdout.flush()

    result = session.ask(ticket, question, settings=settings,
                         on_token=on_token if streaming else None, stream=streaming)
    if args.json:
        _emit(result)
    else:
        sys.stdout.write("\n")
    return 0


def cmd_attach(args):
    ticket = tickets.load(args.ticket)
    added = []
    for path in args.files:
        added.extend(session.attach(ticket, path, note=args.note or "",
                                    frames=args.frames))
    if args.json:
        _emit({"added": added})
        return 0
    for entry in added:
        sys.stdout.write("  %-10s %s%s\n" % (entry["kind"], entry["stored"],
                                             "  (%s)" % entry["note"]
                                             if entry.get("note") else ""))
    return 0


def cmd_list(args):
    found = tickets.listing()
    if args.json:
        _emit({"tickets": found})
        return 0
    if not found:
        sys.stdout.write("no tickets yet - start one with: toolbox assist new \"...\"\n")
        return 0
    for entry in found:
        sys.stdout.write("%-34s %-8s %2d msg %2d files  %s\n"
                         % (entry["id"], entry["status"], entry["messages"],
                            entry["attachments"], entry["title"]))
    return 0


def cmd_show(args):
    ticket = tickets.load(args.ticket)
    if args.json:
        _emit(ticket.detail())
        return 0
    sys.stdout.write("%s\n%s\n\n" % (ticket.title, "=" * len(ticket.title)))
    if ticket.record.get("body"):
        sys.stdout.write("%s\n\n" % ticket.record["body"])
    for entry in ticket.messages:
        who = "you" if entry["role"] == "user" else "assist"
        sys.stdout.write("--- %s (%s) ---\n%s\n\n" % (who, entry["at"], entry["text"]))
    return 0


def cmd_context(args):
    ticket = tickets.load(args.ticket) if args.ticket else None
    gathered = contextmod.gather()
    if ticket:
        ticket.set_context(gathered)
    if args.json:
        _emit(gathered)
        return 0
    sys.stdout.write(contextmod.summarise(gathered) + "\n")
    return 0


def cmd_doctor(args):
    report = session.doctor()
    if args.json:
        _emit(report)
        return 0

    egress = report["egress"]
    sys.stdout.write("model server   %s\n" % report["endpoint"])
    sys.stdout.write("               resolves to %s (%s)\n"
                     % (", ".join(egress["resolves_to"]) or "nothing",
                        egress["classification"]))
    sys.stdout.write("data leaves this machine: %s\n"
                     % ("NO" if not egress["leaves_machine"] else
                        "yes - to %s on your network" % egress["host"]))
    if not egress["allowed"]:
        sys.stdout.write("  refused: %s\n" % egress["reason"])
    sys.stdout.write("server         %s\n" % report["server"])
    if report.get("server_error"):
        sys.stdout.write("               %s\n" % report["server_error"])
    sys.stdout.write("text model     %s%s\n"
                     % (report["models"]["text"],
                        "   NOT PULLED" if report["models"]["text"]
                        in report["missing_models"] else ""))
    sys.stdout.write("vision model   %s%s\n"
                     % (report["models"]["vision"],
                        "   NOT PULLED" if report["models"]["vision"]
                        in report["missing_models"] else ""))
    sys.stdout.write("video support  %s\n"
                     % ("yes" if report["ffmpeg"] else "no - install ffmpeg"))
    sys.stdout.write("tickets in     %s\n" % report["data_dir"])
    if report["missing_models"]:
        sys.stdout.write("\npull what is missing:\n")
        for name in report["missing_models"]:
            sys.stdout.write("    ollama pull %s\n" % name)
    return 0


def cmd_config(args):
    settings = config.load()
    if args.set:
        for pair in args.set:
            if "=" not in pair:
                sys.stderr.write("error: --set wants key=value, got %r\n" % pair)
                return 2
            key, value = pair.split("=", 1)
            if key not in config.DEFAULTS:
                sys.stderr.write("error: unknown setting %r. Known: %s\n"
                                 % (key, ", ".join(sorted(config.DEFAULTS))))
                return 2
            current = config.DEFAULTS[key]
            if isinstance(current, bool):
                value = value.lower() in ("1", "true", "yes", "on")
            elif isinstance(current, int) and not isinstance(current, bool):
                value = int(value)
            elif isinstance(current, float):
                value = float(value)
            settings[key] = value
        path = config.save(settings)
        sys.stderr.write("saved to %s\n" % path)
    if args.json:
        _emit(settings)
        return 0
    for key in sorted(settings):
        sys.stdout.write("%-20s %s\n" % (key, settings[key]))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="toolbox assist",
        description="Work a ticket with a model running on this machine. "
                    "Nothing you give it leaves the computer.")
    parser.add_argument("--version", action="version", version="assist %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    def add_json(target):
        target.add_argument("--json", action="store_true", help="machine-readable output")
        return target

    p = add_json(sub.add_parser("new", help="start a ticket"))
    p.add_argument("title")
    p.add_argument("-b", "--body", help="the description")
    p.add_argument("-f", "--body-file", help="read the description from a file")
    p.add_argument("-a", "--attach", action="append",
                   help="a screenshot or video to attach (repeatable)")
    p.add_argument("--no-context", action="store_true",
                   help="skip gathering what this machine reports")
    p.add_argument("--ask", action="store_true", help="ask the model straight away")
    p.set_defaults(func=cmd_new)

    p = add_json(sub.add_parser("ask", help="put a question to the model"))
    p.add_argument("ticket")
    p.add_argument("question", nargs="*")
    p.set_defaults(func=cmd_ask)

    p = add_json(sub.add_parser("attach", help="add screenshots or video"))
    p.add_argument("ticket")
    p.add_argument("files", nargs="+")
    p.add_argument("-n", "--note", help="what it shows")
    p.add_argument("--frames", type=int, default=6,
                   help="frames to sample from a video (default 6)")
    p.set_defaults(func=cmd_attach)

    p = add_json(sub.add_parser("list", help="every ticket"))
    p.set_defaults(func=cmd_list)

    p = add_json(sub.add_parser("show", help="a ticket and its conversation"))
    p.add_argument("ticket")
    p.set_defaults(func=cmd_show)

    p = add_json(sub.add_parser("context", help="what this machine reports"))
    p.add_argument("ticket", nargs="?", help="attach it to this ticket as well")
    p.set_defaults(func=cmd_context)

    p = add_json(sub.add_parser("doctor", help="is the local model set up, and "
                                               "does anything leave this machine"))
    p.set_defaults(func=cmd_doctor)

    p = add_json(sub.add_parser("config", help="show or change settings"))
    p.add_argument("--set", action="append", metavar="KEY=VALUE")
    p.set_defaults(func=cmd_config)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args) or 0
    except EgressBlocked as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 3
    except (TicketError, ModelError, MediaError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130
    except OSError as exc:
        sys.stderr.write("error: %s\n" % (exc.strerror or exc))
        return 2
