"""`toolbox <part> ...` - the suite's front door."""

import sys

from . import __version__

PARTS = {
    "net": ("Network Tool - measure the network", "nettool.cli"),
    "assist": ("Assist - work a ticket with a local model", "assist.cli"),
}

USAGE = """\
toolbox %s - network diagnostics, and a local AI to make sense of them

  toolbox net <command>       %s
  toolbox assist <command>    %s

Either part also runs on its own as `nettool ...` or `python3 -m assist ...`.
Try `toolbox net --help` or `toolbox assist --help`.
""" % (__version__, PARTS["net"][0], PARTS["assist"][0])


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(USAGE)
        return 0
    if argv[0] in ("-V", "--version"):
        sys.stdout.write("toolbox %s\n" % __version__)
        return 0

    part = argv[0]
    if part not in PARTS:
        sys.stderr.write("error: %r is not a part of toolbox. Try: %s\n"
                         % (part, ", ".join(sorted(PARTS))))
        return 2
    module = __import__(PARTS[part][1], fromlist=["main"])
    return module.main(argv[1:])
