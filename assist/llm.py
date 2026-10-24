"""Talking to a model running on this machine.

Speaks the OpenAI chat-completions shape, which is what Ollama, LM Studio,
llama.cpp's server and vLLM all serve. That means the choice of runner is the
user's and can change without touching anything here - the only thing Assist
insists on is that whatever it is runs locally.

Over urllib rather than a client library, for the same reason as the rest of
Toolbox: no dependency can be audited as easily as no dependency.
"""

import base64
import json
import mimetypes
import os
import urllib.error
import urllib.request

from .privacy import EgressBlocked, is_local_endpoint


class ModelError(Exception):
    """The model server could not be reached, or would not answer."""


class Client(object):
    def __init__(self, endpoint, allow_lan=False, timeout=600):
        ok, reason = is_local_endpoint(endpoint, allow_lan=allow_lan)
        if not ok:
            raise ModelError(reason)
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout

    # --- plumbing --------------------------------------------------------

    def _post(self, path, payload):
        request = urllib.request.Request(
            "%s/%s" % (self.endpoint, path.lstrip("/")),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except EgressBlocked:
            raise
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            raise ModelError("the model server answered %d: %s" % (exc.code, detail))
        except urllib.error.URLError as exc:
            raise ModelError(
                "cannot reach the model server at %s (%s). Is it running? "
                "`ollama serve` starts it, and `assist doctor` checks."
                % (self.endpoint, exc.reason))
        except (OSError, ValueError) as exc:
            raise ModelError("the model server did not answer properly: %s" % exc)

    def models(self):
        """What the server has, so the app can say when a model is not pulled."""
        request = urllib.request.Request("%s/models" % self.endpoint)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read())
        except EgressBlocked:
            raise
        except Exception as exc:
            raise ModelError("cannot list models on %s: %s" % (self.endpoint, exc))
        return [entry.get("id", "") for entry in payload.get("data", [])]

    # --- the one call that matters ---------------------------------------

    def chat(self, model, messages, temperature=0.2, stream=False, on_token=None):
        """A completion. With `stream`, `on_token` is called as text arrives."""
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": bool(stream),
        }
        if not stream:
            answer = self._post("chat/completions", payload)
            return _content_of(answer)
        return self._stream(payload, on_token)

    def _stream(self, payload, on_token):
        request = urllib.request.Request(
            "%s/chat/completions" % self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        collected = []
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                for raw in response:
                    line = raw.decode("utf-8", "replace").strip()
                    if not line.startswith("data:"):
                        continue
                    body = line[5:].strip()
                    if body == "[DONE]":
                        break
                    try:
                        chunk = json.loads(body)
                    except ValueError:
                        continue
                    piece = (chunk.get("choices") or [{}])[0].get("delta", {}).get(
                        "content", "")
                    if piece:
                        collected.append(piece)
                        if on_token:
                            on_token(piece)
        except EgressBlocked:
            raise
        except urllib.error.URLError as exc:
            raise ModelError("the model server stopped answering: %s" % exc.reason)
        return "".join(collected)


def _content_of(answer):
    choices = answer.get("choices") or []
    if not choices:
        raise ModelError("the model returned no answer at all")
    return choices[0].get("message", {}).get("content", "")


def image_part(path, max_bytes=6 * 1024 * 1024):
    """One image, as the content part a vision model expects.

    Inlined as a data URL rather than a file path or a URL, because the model
    server is a separate process - handing it a path would mean it reading our
    files, and handing it a URL would mean somebody fetching one.
    """
    size = os.path.getsize(path)
    if size > max_bytes:
        raise ModelError(
            "%s is %.1f MB, which is more than a model will usefully take. "
            "`assist attach` shrinks screenshots automatically when ffmpeg is "
            "installed." % (os.path.basename(path), size / 1024.0 / 1024.0))
    kind = mimetypes.guess_type(path)[0] or "image/png"
    with open(path, "rb") as handle:
        encoded = base64.b64encode(handle.read()).decode("ascii")
    return {"type": "image_url",
            "image_url": {"url": "data:%s;base64,%s" % (kind, encoded)}}


def message(role, text, images=()):
    """A chat message, with images only when there are some."""
    if not images:
        return {"role": role, "content": text}
    parts = [{"type": "text", "text": text}]
    parts.extend(image_part(path) for path in images)
    return {"role": role, "content": parts}
