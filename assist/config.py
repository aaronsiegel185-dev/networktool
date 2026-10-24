"""Where Assist keeps things, and which model it talks to."""

import json
import os

DEFAULT_ENDPOINT = "http://127.0.0.1:11434/v1"

# Sensible Ollama defaults. Text first, vision only when a screenshot or a video
# is attached - vision models are larger and slower, and most tickets are words.
DEFAULT_TEXT_MODEL = "llama3.1:8b"
DEFAULT_VISION_MODEL = "llama3.2-vision:11b"


def data_dir():
    """Tickets, attachments and settings, under the user's own data directory."""
    base = os.environ.get("TOOLBOX_HOME")
    if base:
        return base
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return os.path.join(xdg, "toolbox")
    home = os.path.expanduser("~")
    if os.uname().sysname == "Darwin" if hasattr(os, "uname") else False:
        return os.path.join(home, "Library", "Application Support", "toolbox")
    return os.path.join(home, ".local", "share", "toolbox")


def settings_path():
    return os.path.join(data_dir(), "assist.json")


DEFAULTS = {
    "endpoint": DEFAULT_ENDPOINT,
    "text_model": DEFAULT_TEXT_MODEL,
    "vision_model": DEFAULT_VISION_MODEL,
    "allow_lan": False,
    "temperature": 0.2,
    "max_context_frames": 6,
}


def load():
    """Settings, with anything unset falling back to the defaults."""
    settings = dict(DEFAULTS)
    try:
        with open(settings_path(), "r") as handle:
            stored = json.load(handle)
        if isinstance(stored, dict):
            settings.update({k: v for k, v in stored.items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    return settings


def save(settings):
    path = settings_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    keep = {k: v for k, v in settings.items() if k in DEFAULTS}
    with open(path, "w") as handle:
        json.dump(keep, handle, indent=2, sort_keys=True)
    return path
