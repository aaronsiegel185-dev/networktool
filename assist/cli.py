"""The Assist command line."""

import argparse
import json
import sys

from . import (__version__, clients, config, context as contextmod, media,
               notebooks, session, sources as sourcemod)
from .clients import ClientError
from .llm import ModelError
from .media import MediaError
from .notebooks import NotebookError
from .privacy import EgressBlocked
from .sources import SourceError
from .store import StoreError


def _emit(payload):
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def cmd_new(args):
    body = args.body or ""
    if args.body_file:
        with open(args.body_file, "r") as handle:
            body = handle.read()
    client = _client_for(args.client) if args.client else None
    notebook = notebooks.create(args.title, body,
                                client=client.id if client else None)
    if client:
        sys.stderr.write("filed under %s\n" % client.name)
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


def _client_for(text):
    """A client by id or name, created on the spot if asked for by name.

    Typing a client that does not exist is far more often a typo than an
    intention to create one, so this resolves and reports rather than
    silently making a second client with a slightly different name.
    """
    client = clients.resolve(text)
    if client is None:
        raise ClientError(
            "no client matches %r. Make one with: toolbox assist client new %r"
            % (text, text))
    return client


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
    only = _client_for(args.client).id if args.client else None
    found = notebooks.listing(client=only)
    if args.json:
        _emit({"notebooks": found})
        return 0
    if not found:
        sys.stdout.write("no notebooks yet - start one with: "
                         "toolbox assist new \"...\"\n")
        return 0
    if args.flat or only:
        for entry in found:
            _notebook_row(entry)
        return 0
    # Grouped, because a list of fifty tickets across eight clients is not a
    # list anyone can read. Unfiled last: it is the pile to work through.
    groups = {}
    for entry in found:
        groups.setdefault(entry["client"], []).append(entry)
    named = sorted((key for key in groups if key),
                   key=lambda key: groups[key][0]["client_name"].lower())
    for key in named + ([""] if "" in groups else []):
        label = groups[key][0]["client_name"] if key else "(no client)"
        sys.stdout.write("\n%s\n" % label)
        for entry in groups[key]:
            _notebook_row(entry, indent="  ")
    return 0


def _notebook_row(entry, indent=""):
    """Title first: it is what you are looking for. The id is what you type,
    so it goes last, where a long one can run off the edge without pushing
    everything else out of line."""
    title = entry["title"]
    if len(title) > 44:
        title = title[:43] + "\u2026"
    status = "" if entry["status"] == "open" else "  [%s]" % entry["status"]
    sys.stdout.write("%s%-44s %2d msg  %d/%d src%s   %s\n"
                     % (indent, title, entry["messages"], entry["sources_on"],
                        entry["sources"], status, entry["id"]))


def cmd_show(args):
    notebook = notebooks.load(args.notebook)
    if args.json:
        _emit(notebook.detail())
        return 0
    sys.stdout.write("%s\n%s\n" % (notebook.title, "=" * len(notebook.title)))
    client = notebook.client()
    if client:
        sys.stdout.write("for %s\n" % client.name)
    sys.stdout.write("\n")
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


# --- clients ---------------------------------------------------------------

def cmd_client_new(args):
    client = clients.create(args.name, notes=args.notes or "")
    for pair in args.fact or []:
        label, _, value = pair.partition("=")
        client.add_fact(label, value)
    for path in args.add or []:
        client.add_source(path)
    client.tidy_staging()
    if args.json:
        _emit(client.detail())
        return 0
    sys.stdout.write("client %s\n  %s\n" % (client.id, client.directory))
    sys.stdout.write("\nnow:  toolbox assist client set %s --fact firewall=203.0.113.1\n"
                     % client.id)
    sys.stdout.write("      toolbox assist new \"...\" --client %s\n" % client.id)
    return 0


def cmd_client_list(args):
    found = clients.listing()
    if args.json:
        _emit({"clients": found})
        return 0
    if not found:
        sys.stdout.write("no clients yet - make one with: "
                         "toolbox assist client new \"Acme Corp\"\n")
        return 0
    for entry in found:
        sys.stdout.write("%-24s %2d notebooks  %2d facts  %2d sources  %s\n"
                         % (entry["id"], entry["notebooks"], entry["facts"],
                            entry["sources"], entry["name"]))
    return 0


def cmd_client_show(args):
    client = _client_for(args.client)
    if args.json:
        _emit(client.detail())
        return 0
    sys.stdout.write("%s\n%s\n\n" % (client.name, "=" * len(client.name)))
    grouped = client.grouped_facts()
    if grouped:
        width = max(len(label) for label, _ in grouped)
        for label, values in grouped:
            sys.stdout.write("  %-*s  %s\n" % (width, label, ", ".join(values)))
        sys.stdout.write("\n")
    if client.notes:
        sys.stdout.write("%s\n\n" % client.notes)
    if client.sources:
        sys.stdout.write("kept on file:\n")
        for entry in client.sources:
            sys.stdout.write("  %s %-11s %-28s %s\n"
                             % ("on " if entry.get("enabled", True) else "off",
                                entry["kind"], entry["stored"], entry.get("note", "")))
        sys.stdout.write("\n")
    found = notebooks.listing(client=client.id)
    if found:
        sys.stdout.write("notebooks:\n")
        for entry in found:
            sys.stdout.write("  %-34s %s\n" % (entry["id"], entry["title"]))
    return 0


def cmd_client_set(args):
    client = _client_for(args.client)
    for pair in args.fact or []:
        label, separator, value = pair.partition("=")
        if not separator:
            sys.stderr.write("error: --fact wants label=value, got %r\n" % pair)
            return 2
        client.add_fact(label, value)
    for text in args.forget or []:
        label, separator, value = text.partition("=")
        dropped = client.forget(label, value if separator else None)
        sys.stderr.write("forgot %d\n" % dropped)
    if args.name:
        client.set_name(args.name)
    if args.notes is not None:
        client.set_notes(args.notes)
    if args.note:
        client.append_note(args.note)
    if args.notes_file:
        with open(args.notes_file) as handle:
            client.set_notes(handle.read())
    if args.json:
        _emit(client.detail())
        return 0
    return cmd_client_show(args)


def cmd_client_add(args):
    client = _client_for(args.client)
    added = []
    for path in args.files:
        entry = client.add_source(path, note=args.note or "", frames=args.frames)
        added.append(entry)
        added.extend(child for child in client.sources
                     if child.get("parent") == entry["stored"] and child not in added)
    client.tidy_staging()
    if args.json:
        _emit({"added": added})
        return 0
    for entry in added:
        sys.stdout.write("  %-11s %-28s %s\n"
                         % (entry["kind"], entry["stored"], entry.get("note", "")))
    return 0


def cmd_client_sources(args):
    client = _client_for(args.client)
    for name in args.on or []:
        client.set_source_enabled(name, True)
    for name in args.off or []:
        client.set_source_enabled(name, False)
    for name in args.remove or []:
        client.remove_source(name)
    if args.json:
        _emit({"sources": client.source_detail()})
        return 0
    if not client.sources:
        sys.stdout.write("nothing on file for %s\n" % client.name)
        return 0
    for entry in client.sources:
        sys.stdout.write("  %s %-11s %-28s %s\n"
                         % ("on " if entry.get("enabled", True) else "off",
                            entry["kind"], entry["stored"], entry.get("note", "")))
    return 0


def cmd_client_remove(args):
    client = _client_for(args.client)
    found = notebooks.listing(client=client.id)
    if found and not args.yes:
        sys.stderr.write("%s has %d notebook(s). They will be kept and unfiled.\n"
                         "Re-run with --yes to go ahead.\n"
                         % (client.name, len(found)))
        return 2
    orphaned = clients.remove(client.id)
    sys.stderr.write("removed %s; %d notebook(s) kept and unfiled\n"
                     % (client.name, orphaned))
    return 0


def cmd_file(args):
    """Move a notebook to a client, or out of one."""
    notebook = notebooks.load(args.notebook)
    if args.none:
        notebook.set_client(None)
        sys.stderr.write("%s is no longer filed under a client\n" % notebook.id)
        return 0
    client = _client_for(args.client)
    notebook.set_client(client.id)
    if args.json:
        _emit(notebook.summary())
        return 0
    sys.stdout.write("%s filed under %s\n" % (notebook.id, client.name))
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
    p.add_argument("-c", "--client", help="file it under this client")
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

    p = add_json(sub.add_parser("list", help="every notebook, grouped by client"))
    p.add_argument("-c", "--client", help="only this client's")
    p.add_argument("--flat", action="store_true", help="one list, no grouping")
    p.set_defaults(func=cmd_list)

    p = add_json(sub.add_parser("file", help="move a notebook to a client"))
    p.add_argument("notebook")
    p.add_argument("client", nargs="?")
    p.add_argument("--none", action="store_true", help="unfile it instead")
    p.set_defaults(func=cmd_file)

    # Clients get their own group: there are enough verbs that flattening them
    # into the top level would bury the four commands people use every day.
    client = sub.add_parser("client", help="who a notebook is for, and what is "
                                           "permanently true about their setup")
    csub = client.add_subparsers(dest="client_command")
    client.set_defaults(func=lambda a: (client.print_help(), 0)[1])

    p = add_json(csub.add_parser("new", help="start a client"))
    p.add_argument("name")
    p.add_argument("--notes", help="free text about them")
    p.add_argument("--fact", action="append", metavar="LABEL=VALUE",
                   help="e.g. --fact firewall=203.0.113.1 (repeatable)")
    p.add_argument("-a", "--add", action="append", metavar="FILE",
                   help="reference material to keep on file (repeatable)")
    p.set_defaults(func=cmd_client_new)

    p = add_json(csub.add_parser("list", help="every client"))
    p.set_defaults(func=cmd_client_list)

    p = add_json(csub.add_parser("show", help="a client, their facts and "
                                              "their notebooks"))
    p.add_argument("client")
    p.set_defaults(func=cmd_client_show)

    p = add_json(csub.add_parser("set", help="record what is true about them"))
    p.add_argument("client")
    p.add_argument("--fact", action="append", metavar="LABEL=VALUE",
                   help="repeatable; the same label may hold several values")
    p.add_argument("--forget", action="append", metavar="LABEL[=VALUE]",
                   help="drop every value under a label, or one exact pair")
    p.add_argument("--name", help="rename them")
    p.add_argument("--note", help="append a line to the notes")
    p.add_argument("--notes", help="replace the notes")
    p.add_argument("--notes-file", help="replace the notes from a file")
    p.set_defaults(func=cmd_client_set)

    p = add_json(csub.add_parser("add", help="keep reference material on file"))
    p.add_argument("client")
    p.add_argument("files", nargs="+")
    p.add_argument("-n", "--note", help="what it shows")
    p.add_argument("--frames", type=int, default=6)
    p.set_defaults(func=cmd_client_add)

    p = add_json(csub.add_parser("sources", help="what is on file, and whether "
                                                 "it is being sent"))
    p.add_argument("client")
    p.add_argument("--on", action="append", metavar="NAME")
    p.add_argument("--off", action="append", metavar="NAME")
    p.add_argument("--remove", action="append", metavar="NAME")
    p.set_defaults(func=cmd_client_sources)

    p = add_json(csub.add_parser("remove", help="delete a client, keeping "
                                                "their notebooks"))
    p.add_argument("client")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_client_remove)

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
    except (StoreError, NotebookError, ClientError, SourceError,
            ModelError, MediaError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130
    except OSError as exc:
        sys.stderr.write("error: %s\n" % (exc.strerror or exc))
        return 2
