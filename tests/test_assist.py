"""Notebooks, media and the exchange with the model."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from assist import config, context, llm, media, notebooks, session
from tests.assist_stub import StubModelServer

HAVE_FFMPEG = shutil.which("ffmpeg") is not None


def png(path, width=120, height=80):
    """A real PNG, via ffmpeg where possible and a stub header otherwise."""
    if HAVE_FFMPEG:
        subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "lavfi",
                        "-i", "testsrc=duration=1:size=%dx%d:rate=1" % (width, height),
                        "-frames:v", "1", path], check=True)
    else:
        with open(path, "wb") as handle:
            handle.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    return path


def text_file(path, body):
    with open(path, "w") as handle:
        handle.write(body)
    return path


class AssistCase(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self._saved = os.environ.get("TOOLBOX_HOME")
        os.environ["TOOLBOX_HOME"] = self.home
        self.work = tempfile.mkdtemp()

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("TOOLBOX_HOME", None)
        else:
            os.environ["TOOLBOX_HOME"] = self._saved


class TestNotebooks(AssistCase):
    def test_a_notebook_round_trips(self):
        notebook = notebooks.create("Printer keeps vanishing", "Only after sleep.")
        notebook.add_message("user", "It came back after a reboot.")
        reloaded = notebooks.load(notebook.id)
        self.assertEqual(reloaded.title, "Printer keeps vanishing")
        self.assertEqual(len(reloaded.messages), 1)

    def test_the_id_is_readable_and_sorts_by_time(self):
        notebook = notebooks.create("Wi-Fi drops every afternoon")
        self.assertIn("wi-fi-drops-every-afternoon", notebook.id)
        self.assertRegex(notebook.id, r"^\d{8}-\d{6}-")

    def test_adding_a_source_copies_and_leaves_the_original(self):
        source = png(os.path.join(self.work, "shot.png"))
        notebook = notebooks.create("With evidence")
        notebook.add_source(source)
        self.assertTrue(os.path.exists(source), "the user's own file is not moved")
        self.assertEqual(len(notebook.sources), 1)
        self.assertTrue(os.path.exists(notebook.path_of(notebook.sources[0])))

    def test_two_files_of_the_same_name_do_not_overwrite(self):
        notebook = notebooks.create("Two shots")
        first = png(os.path.join(self.work, "shot.png"))
        second_dir = tempfile.mkdtemp()
        second = png(os.path.join(second_dir, "shot.png"))
        notebook.add_source(first)
        notebook.add_source(second)
        stored = sorted(entry["stored"] for entry in notebook.sources)
        self.assertEqual(len(stored), 2)
        self.assertNotEqual(stored[0], stored[1])

    def test_a_source_can_be_switched_off_without_being_deleted(self):
        notebook = notebooks.create("Selective")
        notebook.add_source(text_file(os.path.join(self.work, "a.log"), "one\ntwo\n"))
        notebook.set_source_enabled("a.log", False)
        self.assertEqual(len(notebook.sources), 1)
        self.assertEqual(notebook.enabled_sources(), [])
        self.assertTrue(os.path.exists(notebook.path_of(notebook.sources[0])),
                        "switching off must not delete the file")
        notebook.set_source_enabled("a.log", True)
        self.assertEqual(len(notebook.enabled_sources()), 1)

    def test_removing_a_source_deletes_its_file(self):
        notebook = notebooks.create("Gone")
        notebook.add_source(text_file(os.path.join(self.work, "a.log"), "one\n"))
        path = notebook.path_of(notebook.sources[0])
        notebook.remove_source("a.log")
        self.assertEqual(notebook.sources, [])
        self.assertFalse(os.path.exists(path))

    def test_an_unknown_source_name_says_so(self):
        notebook = notebooks.create("Nothing here")
        with self.assertRaises(notebooks.NotebookError):
            notebook.set_source_enabled("nope.log", False)

    def test_detail_resolves_source_paths_without_storing_them(self):
        notebook = notebooks.create("With evidence")
        notebook.add_source(png(os.path.join(self.work, "shot.png")))
        detail = notebook.detail()
        path = detail["sources"][0]["path"]
        self.assertTrue(os.path.isfile(path), path)
        self.assertEqual(detail["directory"], notebook.directory)
        # The record on disk stays portable: no absolute path to this machine's
        # notebook store is written into it.
        with open(os.path.join(notebook.directory, "notebook.json")) as handle:
            on_disk = json.load(handle)
        self.assertNotIn("path", on_disk["sources"][0])
        self.assertNotIn("directory", on_disk)

    def test_detail_does_not_mutate_the_record(self):
        notebook = notebooks.create("Untouched")
        notebook.add_source(png(os.path.join(self.work, "shot.png")))
        notebook.detail()
        self.assertNotIn("path", notebook.sources[0])
        self.assertNotIn("directory", notebook.record)

    def test_a_missing_notebook_says_so(self):
        with self.assertRaises(notebooks.NotebookError):
            notebooks.load("20200101-000000-nothing")

    def test_listing_is_newest_first(self):
        notebooks.create("older")
        newer = notebooks.create("newer")
        listed = notebooks.listing()
        self.assertEqual(listed[0]["id"], newer.id)


class TestMigration(AssistCase):
    """A rename must not strand work someone already did."""

    def _old_ticket(self, with_pcap=False):
        root = os.path.join(self.home, "tickets", "20260101-120000-old")
        os.makedirs(os.path.join(root, "attachments"))
        png(os.path.join(root, "attachments", "shot.png"))
        attachments = [{"stored": "shot.png", "original": "/old/shot.png",
                        "kind": "screenshot", "note": "the error", "bytes": 1,
                        "at": "2026-01-01T12:00:02"}]
        if with_pcap:
            text_file(os.path.join(root, "attachments", "notes.log"), "a\nb\n")
            attachments.append({"stored": "notes.log", "original": "/old/notes.log",
                                "kind": "file", "note": "", "bytes": 4,
                                "at": "2026-01-01T12:00:03"})
        # Deliberately the OLD filename and shape: this is what migration reads.
        with open(os.path.join(root, "ticket.json"), "w") as handle:
            json.dump({"id": "20260101-120000-old", "title": "An older ticket",
                       "body": "From before notebooks.", "status": "open",
                       "created": "2026-01-01T12:00:00", "context": {},
                       "messages": [{"role": "user", "text": "why is it slow?",
                                     "images": [], "at": "2026-01-01T12:00:01"}],
                       "attachments": attachments}, handle)
        return root

    def test_an_old_ticket_becomes_a_notebook(self):
        self._old_ticket()
        listed = notebooks.listing()
        self.assertEqual([entry["id"] for entry in listed], ["20260101-120000-old"])
        notebook = notebooks.load("20260101-120000-old")
        self.assertEqual(notebook.title, "An older ticket")
        self.assertEqual(len(notebook.messages), 1)
        self.assertEqual(len(notebook.sources), 1)
        self.assertEqual(notebook.sources[0]["kind"], "screenshot")
        self.assertTrue(os.path.exists(notebook.path_of(notebook.sources[0])),
                        "the attachment file came across too")

    def test_a_migrated_attachment_is_reclassified_and_rendered(self):
        # The old layout called anything non-media a "file" and never rendered
        # it, so a migrated source has to be looked at again to be useful.
        self._old_ticket(with_pcap=True)
        notebook = notebooks.load(notebooks.listing()[0]["id"])
        log = [entry for entry in notebook.sources if entry["stored"] == "notes.log"][0]
        self.assertEqual(log["kind"], "log")
        self.assertIn("a", log["digest"])

    def test_migrating_twice_does_not_duplicate(self):
        self._old_ticket()
        notebooks.listing()
        notebooks.listing()
        self.assertEqual(len(notebooks.listing()), 1)


class TestMedia(AssistCase):
    def test_an_image_is_recognised_by_its_bytes(self):
        self.assertEqual(media.sniff(png(os.path.join(self.work, "a.png"))), "image")

    def test_something_that_is_not_media_is_not_claimed_to_be(self):
        path = os.path.join(self.work, "notes.txt")
        with open(path, "w") as handle:
            handle.write("just some words")
        self.assertEqual(media.sniff(path), "other")

    @unittest.skipUnless(HAVE_FFMPEG, "needs ffmpeg")
    def test_a_video_is_recognised_and_measured(self):
        path = os.path.join(self.work, "clip.mp4")
        subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "lavfi",
                        "-i", "testsrc=duration=4:size=320x240:rate=10", path],
                       check=True)
        self.assertEqual(media.sniff(path), "video")
        described = media.describe(path)
        self.assertAlmostEqual(described["duration_s"], 4.0, delta=0.5)

    @unittest.skipUnless(HAVE_FFMPEG, "needs ffmpeg")
    def test_an_oversized_screenshot_is_shrunk(self):
        big = png(os.path.join(self.work, "big.png"), 3000, 2000)
        small = media.shrink(big, os.path.join(self.work, "out"))
        self.assertNotEqual(small, big)
        self.assertLessEqual(media.describe(small)["width"], media.MAX_DIMENSION)

    @unittest.skipUnless(HAVE_FFMPEG, "needs ffmpeg")
    def test_a_small_screenshot_is_left_alone(self):
        # Re-encoding a screenshot that is already small costs quality for nothing.
        small = png(os.path.join(self.work, "small.png"), 800, 600)
        self.assertEqual(media.shrink(small, os.path.join(self.work, "out")), small)

    @unittest.skipUnless(HAVE_FFMPEG, "needs ffmpeg")
    def test_frames_are_spread_across_the_whole_video(self):
        # The interesting moment in a recording of a fault is rarely at the start.
        path = os.path.join(self.work, "clip.mp4")
        subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "lavfi",
                        "-i", "testsrc=duration=10:size=320x240:rate=10", path],
                       check=True)
        frames = media.extract_frames(path, os.path.join(self.work, "frames"), count=4)
        self.assertEqual(len(frames), 4)
        times = [frame["at_s"] for frame in frames]
        self.assertEqual(times, sorted(times))
        self.assertGreater(times[0], 0, "not all bunched at zero")
        self.assertLess(times[-1], 10)
        self.assertGreater(times[-1] - times[0], 5, "spread across the clip")


class TestSession(AssistCase):
    def settings(self, server):
        return {"endpoint": server.endpoint, "text_model": "llama3.1:8b",
                "vision_model": "llama3.2-vision:11b", "allow_lan": False,
                "temperature": 0.2}

    def test_text_tickets_use_the_text_model(self):
        notebook = notebooks.create("No pictures here")
        model, vision = session.pick_model(notebook, config.DEFAULTS)
        self.assertEqual(model, config.DEFAULT_TEXT_MODEL)
        self.assertFalse(vision)

    def test_a_screenshot_switches_to_the_vision_model(self):
        notebook = notebooks.create("With a screenshot")
        session.add_source(notebook, png(os.path.join(self.work, "shot.png")))
        model, vision = session.pick_model(notebook, config.DEFAULTS)
        self.assertEqual(model, config.DEFAULT_VISION_MODEL)
        self.assertTrue(vision)

    def test_the_prompt_carries_the_ticket_and_the_measurements(self):
        notebook = notebooks.create("Wi-Fi drops", "Only on 5 GHz.")
        notebook.set_context({"system": {"platform": "Darwin-24", "hostname": "mac"},
                            "dns": {"servers": ["192.168.1.1"], "search": []}})
        messages = session.build_messages(notebook)
        self.assertEqual(messages[0]["role"], "system")
        text = messages[1]["content"]
        self.assertIn("Wi-Fi drops", text)
        self.assertIn("Only on 5 GHz", text)
        self.assertIn("192.168.1.1", text, "the gathered facts go in")

    def test_images_are_inlined_not_referenced(self):
        # The model server is a separate process: handing it a path would make it
        # read our files, and a URL would make somebody fetch one.
        notebook = notebooks.create("Look at this")
        session.add_source(notebook, png(os.path.join(self.work, "shot.png")))
        parts = session.build_messages(notebook)[1]["content"]
        images = [p for p in parts if p.get("type") == "image_url"]
        self.assertEqual(len(images), 1)
        self.assertTrue(images[0]["image_url"]["url"].startswith("data:image/"))

    def test_only_the_most_recent_images_are_sent(self):
        notebook = notebooks.create("Many shots")
        for index in range(9):
            session.add_source(notebook, png(os.path.join(self.work, "s%d.png" % index)))
        parts = session.build_messages(notebook, image_limit=4)[1]["content"]
        self.assertEqual(sum(1 for p in parts if p.get("type") == "image_url"), 4)

    def test_a_full_exchange_against_a_server(self):
        with StubModelServer(reply="Move to channel 149.") as server:
            notebook = notebooks.create("Congested channel")
            streamed = []
            result = session.ask(notebook, "what now?", settings=self.settings(server),
                                 on_token=streamed.append, stream=True)
            self.assertEqual(result["answer"].strip(), "Move to channel 149.")
            self.assertTrue(streamed, "streaming delivers text as it arrives")
            self.assertEqual([m["role"] for m in notebook.messages],
                             ["user", "assistant"])
            sent = server.requests[-1]
            self.assertEqual(sent["model"], "llama3.1:8b")

    def test_the_conversation_is_replayed_so_it_has_memory(self):
        with StubModelServer(reply="Yes.") as server:
            notebook = notebooks.create("Follow up")
            session.ask(notebook, "first question", settings=self.settings(server))
            session.ask(notebook, "second question", settings=self.settings(server))
            sent = server.requests[-1]["messages"]
            text = json.dumps(sent)
            self.assertIn("first question", text)
            self.assertIn("second question", text)

    def test_a_public_endpoint_is_refused_before_anything_is_sent(self):
        notebook = notebooks.create("Should never be sent")
        settings = dict(config.DEFAULTS, endpoint="http://8.8.8.8:11434/v1")
        with self.assertRaises(llm.ModelError):
            session.ask(notebook, "hello", settings=settings)

    def test_doctor_reports_what_is_reachable(self):
        with StubModelServer() as server:
            report = session.doctor(dict(config.DEFAULTS, endpoint=server.endpoint))
        self.assertEqual(report["server"], "reachable")
        self.assertFalse(report["egress"]["leaves_machine"])
        self.assertIn("llama3.1:8b", report["available_models"])
        self.assertEqual(report["missing_models"], [])

    def test_doctor_names_a_model_that_is_not_pulled(self):
        with StubModelServer(models=("llama3.1:8b",)) as server:
            report = session.doctor(dict(config.DEFAULTS, endpoint=server.endpoint))
        self.assertIn(config.DEFAULT_VISION_MODEL, report["missing_models"])

    def test_doctor_survives_a_server_that_is_not_running(self):
        report = session.doctor(dict(config.DEFAULTS,
                                     endpoint="http://127.0.0.1:1/v1"))
        self.assertEqual(report["server"], "unreachable")
        self.assertIn("server_error", report)


class TestContext(AssistCase):
    def test_a_failing_probe_is_recorded_rather_than_lost(self):
        # "no wireless interface" is itself worth the model knowing.
        def boom():
            raise RuntimeError("no radio here")

        saved = context.PROBES
        context.PROBES = (("wifi", "the radio", boom),)
        try:
            gathered = context.gather()
        finally:
            context.PROBES = saved
        self.assertIn("unavailable", gathered)
        self.assertIn("no radio here", gathered["unavailable"]["wifi"])

    def test_the_summary_is_lines_a_person_could_read(self):
        summary = context.summarise({
            "system": {"platform": "Darwin-24.0", "machine": "arm64",
                       "hostname": "mac", "user": "aarons"},
            "wifi": {"link": {"connected": True, "ssid": "HomeNet", "channel": 48,
                              "band": "5", "signal_dbm": -52, "rating": "excellent",
                              "snr_db": 40, "bssid": "3c:37:86:11:22:33"},
                     "interference": {"channel": 48, "headline_pct": 61.0,
                                      "rating": "heavy", "source": "neighbour model",
                                      "sources": [{"ssid": "Neighbour", "channel": 44,
                                                   "signal_dbm": -58,
                                                   "overlap_pct": 100.0,
                                                   "share_pct": 70.0}]}},
        })
        self.assertIn("HomeNet", summary)
        self.assertIn("61% (heavy", summary)
        self.assertIn("Neighbour", summary)
        self.assertNotIn("{", summary, "facts as prose, not as JSON")

    def test_the_summary_is_capped(self):
        enormous = {"system": {"platform": "x" * 50000}}
        self.assertLessEqual(len(context.summarise(enormous, limit=500)), 520)


if __name__ == "__main__":
    unittest.main()


class TestTextOnlySetup(AssistCase):
    """A machine with no vision model must still work, and say what it cannot see."""

    def test_no_vision_model_falls_back_to_text(self):
        settings = dict(config.DEFAULTS, vision_model="")
        notebook = notebooks.create("With a screenshot")
        notebook.add_source(png(os.path.join(self.work, "shot.png")),
                              kind="screenshot")
        model, used_vision = session.pick_model(notebook, settings)
        self.assertFalse(used_vision)
        self.assertEqual(model, settings["text_model"])

    def test_images_are_not_sent_to_a_text_model(self):
        notebook = notebooks.create("With a screenshot")
        notebook.add_source(png(os.path.join(self.work, "shot.png")),
                              kind="screenshot")
        messages = session.build_messages(notebook, with_images=False)
        blob = json.dumps(messages)
        self.assertNotIn("data:image", blob)
        self.assertIn("cannot see the images in this notebook", blob)

    def test_the_whole_ask_works_without_a_vision_model(self):
        with StubModelServer() as stub:
            settings = dict(config.DEFAULTS, endpoint=stub.endpoint,
                            vision_model="")
            notebook = notebooks.create("Screenshot, no vision model")
            notebook.add_source(png(os.path.join(self.work, "shot.png")),
                                  kind="screenshot")
            result = session.ask(notebook, "what is wrong?", settings=settings,
                                 stream=False)
            self.assertFalse(result["vision"])
            self.assertEqual(result["model"], config.DEFAULTS["text_model"])
            # The request that actually went out carried no image data.
            sent = json.dumps(stub.requests[-1])
            self.assertNotIn("data:image", sent)

    def test_a_vision_model_still_gets_the_image(self):
        with StubModelServer() as stub:
            settings = dict(config.DEFAULTS, endpoint=stub.endpoint)
            notebook = notebooks.create("Screenshot, with vision model")
            notebook.add_source(png(os.path.join(self.work, "shot.png")),
                                  kind="screenshot")
            result = session.ask(notebook, "what is wrong?", settings=settings,
                                 stream=False)
            self.assertTrue(result["vision"])
            self.assertIn("data:image", json.dumps(stub.requests[-1]))
