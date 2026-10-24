"""The Assist command line."""

import argparse
import json
import sys

from . import (__version__, config, context as contextmod, media, notebooks,
               session, sources as sourcemod)
from .llm import ModelError
from .media import MediaError
from .notebooks import NotebookError
from .privacy import EgressBlocked
from .sources import SourceError


def _emit(payload):
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def cmd_new(args):
    body = args.body or ""
    if args.body_file:
        with open(args.body_file, "r") as handle:
            body = handle.read()
    notebook = notebooks.create(args.title, body)
    if not args.no_context:
        sys.stderr.write("gathering what this machine knows...\n")
        notebook.set_context(contextmod.gather(
            on_progress=lambda name, what: sys.stderr.write("  %s\n" % what)))
    for path in args.add or []:
        entry = session.add_source(notebook, path)
        sys.stderr.write("  added %s (%s)\n" % (entry["stored"], entry["note"]))
    if args.json:
        _emit(notebook.summary())
        return 0
    sys.stdout.write("notebook %s\n" % notebook.id)
    sys.stdout.write("  %s\n" % notebook.directory)
    if args.ask:
        return _answer(notebook, None, args)
    sys.stdout.write("\nnow:  toolbox assist add %s capture.pcap\n" % notebook.id)
    sys.stdout.write("      toolbox assist ask %s \"what should I check first?\"\n"
                     % notebook.id)
    return 0


def cmd_ask(args):
    notebook = notebooks.load(args.notebook)
    return _answer(notebook, " ".join(args.question) or None, args)


def _answer(notebook, question, args):
    settings = config.load()
    streaming = not args.json
    if not args.json:
        model, vision = session.pick_model(notebook, settings)
        on = notebook.enabled_sources()
        sys.stderr.write("asking %s%s on %s, from %d source%s\n\n"
                         % (model, " (vision)" if vision else "",
                            settings["endpoint"], len(on), "" if len(on) == 1 else "s"))

    def on_token(piece):
        sys.stdout.write(piece)
        sys.stdout.flush()

    result = session.ask(notebook, question, settings=settings,
                         on_token=on_token if streaming else None, stream=streaming)
    if args.json:
        _emit(result)
    else:
        sys.stdout.write("\n")
    return 0


def cmd_add(args):
    """Add files to a notebook as sources."""
    notebook = notebooks.load(args.notebook)
    added = []
    for path in args.files:
        entry = session.add_source(notebook, path, note=args.note or "",
                                   frames=args.frames)
        added.append(entry)
        # A recording brings its frames with it; show those too.
        added.extend(child for child in notebook.sources
                     if child.get("parent") == entry["stored"]
                     and child not in added)
    if args.json:
        _emit({"added": added})
        return 0
    for entry in added:
        sys.stdout.write("  %-11s %-28s %s\n"
                         % (entry["kind"], entry["stored"], entry.get("note", "")))
    return 0


def cmd_sources(args):
    """List the sources in a notebook, or switch them on and off."""
    notebook = notebooks.load(args.notebook)
    for name in args.on or []:
        notebook.set_source_enabled(name, True)
    for name in args.off or []:
        notebook.set_source_enabled(name, False)
    for name in args.remove or []:
        count = notebook.remove_source(name)
        sys.stderr.write("removed %s%s\n"
                         % (name, " and %d derived from it" % (count - 1)
                            if count > 1 else ""))
    if args.json:
        _emit({"sources": notebook.detail()["sources"]})
        return 0
    if not notebook.sources:
        sys.stdout.write("no sources yet - add one with: "
                         "toolbox assist add %s <file>\n" % notebook.id)
        return 0
    for entry in notebook.sources:
        sys.stdout.write("  %s %-11s %-28s %s\n"
                         % ("on " if entry.get("enabled", True) else "off",
                            entry["kind"], entry["stored"], entry.get("note", "")))
    return 0


def cmd_list(args):
    found = notebooks.listing()
    if args.json:
        _emit({"notebooks": found})
        return 0
    if not found:
        sys.stdout.write("no notebooks yet - start one with: "
                         "toolbox assist new \"...\"\n")
        return 0
    for entry in found:
        sys.stdout.write("%-34s %-8s %2d msg %2d/%-2d src  %s\n"
                         % (entry["id"], entry["status"], entry["messages"],
                            entry["sources_on"], entry["sources"], entry["title"]))
    return 0


def cmd_show(args):
    notebook = notebooks.load(args.notebook)
    if args.json:
        _emit(notebook.detail())
        return 0
    sys.stdout.write("%s\n%s\n\n" % (notebook.title, "=" * len(notebook.title)))
    if notebook.record.get("body"):
        sys.stdout.write("%s\n\n" % notebook.record["body"])
    if notebook.sources:
        sys.stdout.write("sources:\n")
        for entry in notebook.sources:
            sys.stdout.write("  %s %-11s %-28s %s\n"
                             % ("on " if entry.get("enabled", True) else "off",
                                entry["kind"], entry["stored"], entry.get("note", "")))
        sys.stdout.write("\n")
    for entry in notebook.messages:
        who = "you" if entry["role"] == "user" else "assist"
        sys.stdout.write("--- %s (%s) ---\n%s\n\n" % (who, entry["at"], entry["text"]))
    return 0


def cmd_prompt(args):
    """Exactly what would be sent to the model, and nothing more.

    The point of a local model is that you can check this. Being able to read
    the prompt is what turns "nothing leaves" from a claim into something
    someone can verify for themselves.
    """
    notebook = notebooks.load(args.notebook)
    settings = config.load()
    _model, vision = session.pick_model(notebook, settings)
    messages = session.build_messages(notebook, with_images=vision)
    if args.json:
        _emit(messages)
        return 0
    for message in messages:
        content = message["content"]
        if isinstance(content, list):
            content = "\n".join(
                part.get("text", "[image]") if part.get("type") == "text" else "[image]"
                for part in content)
        sys.stdout.write("--- %s ---\n%s\n\n" % (message["role"], content))
    return 0


def cmd_context(args):
    notebook = notebooks.load(args.notebook) if args.notebook else None
    gathered = contextmod.gather()
    if notebook:
        notebook.set_context(gathered)
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
    sys.stdout.write("notebooks in   %s\n" % report["data_dir"])
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
        description="A notebook, the files it is grounded in, and a model "
                    "running on this machine. Nothing you give it leaves the "
                    "computer.")
    parser.add_argument("--version", action="version", version="assist %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    def add_json(target):
        target.add_argument("--json", action="store_true", help="machine-readable output")
        return target

    p = add_json(sub.add_parser("new", help="start a notebook"))
    p.add_argument("title")
    p.add_argument("-b", "--body", help="the question, in your own words")
    p.add_argument("-f", "--body-file", help="read the question from a file")
    p.add_argument("-a", "--add", action="append", metavar="FILE",
                   help="a source to add: pcap, log, config, screenshot, "
                        "recording (repeatable)")
    p.add_argument("--no-context", action="store_true",
                   help="skip gathering what this machine reports")
    p.add_argument("--ask", action="store_true", help="ask the model straight away")
    p.set_defaults(func=cmd_new)

    p = add_json(sub.add_parser("ask", help="put a question to the model"))
    p.add_argument("notebook")
    p.add_argument("question", nargs="*")
    p.set_defaults(func=cmd_ask)

    p = add_json(sub.add_parser("add", help="add sources to a notebook"))
    p.add_argument("notebook")
    p.add_argument("files", nargs="+")
    p.add_argument("-n", "--note", help="what it shows")
    p.add_argument("--frames", type=int, default=6,
                   help="frames to sample from a recording (default 6)")
    p.set_defaults(func=cmd_add)

    p = add_json(sub.add_parser("sources", help="list sources, or switch them "
                                                "on and off"))
    p.add_argument("notebook")
    p.add_argument("--on", action="append", metavar="NAME",
                   help="include this source in what the model is told")
    p.add_argument("--off", action="append", metavar="NAME",
                   help="keep the file, but stop sending it")
    p.add_argument("--remove", action="append", metavar="NAME",
                   help="delete the source and anything derived from it")
    p.set_defaults(func=cmd_sources)

    p = add_json(sub.add_parser("list", help="every notebook"))
    p.set_defaults(func=cmd_list)

    p = add_json(sub.add_parser("show", help="a notebook, its sources and its "
                                             "conversation"))
    p.add_argument("notebook")
    p.set_defaults(func=cmd_show)

    p = add_json(sub.add_parser("prompt", help="exactly what would be sent to "
                                               "the model"))
    p.add_argument("notebook")
    p.set_defaults(func=cmd_prompt)

    p = add_json(sub.add_parser("context", help="what this machine reports"))
    p.add_argument("notebook", nargs="?", help="store it in this notebook too")
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
    except (NotebookError, SourceError, ModelError, MediaError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130
    except OSError as exc:
        sys.stderr.write("error: %s\n" % (exc.strerror or exc))
        return 2
