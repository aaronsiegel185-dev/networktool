"""Screenshots and video, turned into something a model can look at.

A vision model takes still images, so a screenshot goes in nearly as-is and a
video becomes a handful of frames sampled across it. Both are done with ffmpeg
when it is there, and both degrade honestly when it is not: a screenshot is
still usable un-shrunk, while a video without ffmpeg simply cannot be read and
says so rather than silently attaching nothing.

ffmpeg is the only optional dependency Toolbox has, and it never sees the
network - it reads a local file and writes local files.
"""

import json
import os
import shutil
import subprocess

# What a vision model can actually use. Bigger costs tokens and time for detail
# that is thrown away; a 5K retina screenshot is mostly empty desktop.
MAX_DIMENSION = 1600

IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "image/webp"),
)


class MediaError(Exception):
    pass


def have_ffmpeg():
    return bool(shutil.which("ffmpeg"))


def _run(argv, timeout=120):
    try:
        done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout)
    except FileNotFoundError:
        raise MediaError("%s is not installed" % argv[0])
    except subprocess.TimeoutExpired:
        raise MediaError("%s took too long" % argv[0])
    return done.returncode, done.stdout, done.stderr


def sniff(path):
    """'image', 'video' or 'other', from the file's own bytes."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(16)
    except OSError as exc:
        raise MediaError("cannot read %s: %s" % (path, exc.strerror or exc))
    for magic, _kind in IMAGE_MAGIC:
        if head.startswith(magic):
            return "image"
    # Video containers are varied enough that asking ffprobe beats a magic table.
    if shutil.which("ffprobe"):
        code, out, _err = _run(["ffprobe", "-v", "quiet", "-print_format", "json",
                                "-show_streams", path], timeout=30)
        if code == 0:
            try:
                streams = json.loads(out).get("streams", [])
            except ValueError:
                streams = []
            kinds = {stream.get("codec_type") for stream in streams}
            if "video" in kinds:
                # A single-frame "video" is a still image in a video container.
                return "video" if len(streams) > 1 or _frames(streams) != 1 else "image"
    return "other"


def _frames(streams):
    for stream in streams:
        if stream.get("codec_type") == "video":
            try:
                return int(stream.get("nb_frames", 0))
            except (TypeError, ValueError):
                return 0
    return 0


def describe(path):
    """Width, height and duration where they can be had."""
    info = {"path": os.path.abspath(path), "bytes": os.path.getsize(path),
            "kind": sniff(path)}
    if not shutil.which("ffprobe"):
        return info
    code, out, _err = _run(["ffprobe", "-v", "quiet", "-print_format", "json",
                            "-show_format", "-show_streams", path], timeout=30)
    if code != 0:
        return info
    try:
        payload = json.loads(out)
    except ValueError:
        return info
    for stream in payload.get("streams", []):
        if stream.get("codec_type") == "video":
            info["width"] = stream.get("width")
            info["height"] = stream.get("height")
            break
    duration = (payload.get("format") or {}).get("duration")
    if duration:
        try:
            info["duration_s"] = round(float(duration), 2)
        except ValueError:
            pass
    return info


def shrink(path, target_dir, max_dimension=MAX_DIMENSION):
    """A copy no larger than max_dimension on its long edge.

    Returns the original path when nothing needs doing or ffmpeg is absent -
    an un-shrunk screenshot still works, it just costs more to look at.
    """
    info = describe(path)
    width, height = info.get("width"), info.get("height")
    if not have_ffmpeg() or not width or not height:
        return path
    if max(width, height) <= max_dimension:
        return path
    os.makedirs(target_dir, exist_ok=True)
    root, _extension = os.path.splitext(os.path.basename(path))
    target = os.path.join(target_dir, "%s-small.png" % root)
    # -1 keeps the aspect ratio; the long edge is whichever is larger.
    scale = ("scale=%d:-1" % max_dimension if width >= height
             else "scale=-1:%d" % max_dimension)
    code, _out, err = _run(["ffmpeg", "-y", "-v", "error", "-i", path,
                            "-vf", scale, target])
    if code != 0 or not os.path.exists(target):
        return path
    return target


def extract_frames(path, target_dir, count=6):
    """Still frames sampled evenly across a video.

    Evenly rather than at the start: the interesting moment in a screen
    recording of a fault is rarely in the first second.
    """
    if not have_ffmpeg():
        raise MediaError(
            "reading video needs ffmpeg, which is not installed. Install it "
            "(`brew install ffmpeg` on a Mac) or attach screenshots instead.")
    info = describe(path)
    duration = info.get("duration_s") or 0
    if duration <= 0:
        raise MediaError("%s has no duration ffprobe can read, so it cannot be "
                         "sampled" % os.path.basename(path))
    os.makedirs(target_dir, exist_ok=True)
    root, _extension = os.path.splitext(os.path.basename(path))
    frames = []
    count = max(1, min(count, 12))
    for index in range(count):
        # Offset into each slice rather than at its edge, which on a short clip
        # would put the first frame at 0.0 and the last past the end.
        at = duration * (index + 0.5) / count
        target = os.path.join(target_dir, "%s-frame%02d.png" % (root, index + 1))
        code, _out, err = _run([
            "ffmpeg", "-y", "-v", "error", "-ss", "%.3f" % at, "-i", path,
            "-frames:v", "1", "-vf", "scale='min(%d,iw)':-1" % MAX_DIMENSION, target])
        if code == 0 and os.path.exists(target):
            frames.append({"path": target, "at_s": round(at, 2)})
    if not frames:
        raise MediaError("ffmpeg could not read any frames out of %s"
                         % os.path.basename(path))
    return frames
