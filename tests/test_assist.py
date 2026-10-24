"""Tickets, media and the exchange with the model."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from assist import config, context, llm, media, session, tickets
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


class TestTickets(AssistCase):
    def test_a_ticket_round_trips(self):
        ticket = tickets.create("Printer keeps vanishing", "Only after sleep.")
        ticket.add_message("user", "It came back after a reboot.")
        reloaded = tickets.load(ticket.id)
        self.assertEqual(reloaded.title, "Printer keeps vanishing")
        self.assertEqual(len(reloaded.messages), 1)

    def test_the_id_is_readable_and_sorts_by_time(self):
        ticket = tickets.create("Wi-Fi drops every afternoon")
        self.assertIn("wi-fi-drops-every-afternoon", ticket.id)
        self.assertRegex(ticket.id, r"^\d{8}-\d{6}-")

    def test_attaching_copies_and_leaves_the_original(self):
        source = png(os.path.join(self.work, "shot.png"))
        ticket = tickets.create("With evidence")
        ticket.add_attachment(source, kind="screenshot")
        self.assertTrue(os.path.exists(source), "the user's own file is not moved")
        self.assertTrue(os.path.exists(
            os.path.join(ticket.attachment_dir, "shot.png")))

    def test_two_files_of_the_same_name_do_not_overwrite(self):
        ticket = tickets.create("Two shots")
        first = png(os.path.join(self.work, "shot.png"))
        second_dir = tempfile.mkdtemp()
        second = png(os.path.join(second_dir, "shot.png"))
        ticket.add_attachment(first, kind="screenshot")
        ticket.add_attachment(second, kind="screenshot")
        stored = sorted(entry["stored"] for entry in ticket.attachments)
        self.assertEqual(stored, ["shot-1.png", "shot.png"])

    def test_a_missing_ticket_says_so(self):
        with self.assertRaises(tickets.TicketError):
            tickets.load("20200101-000000-nothing")

    def test_listing_is_newest_first(self):
        tickets.create("older")
        newer = tickets.create("newer")
        listed = tickets.listing()
        self.assertEqual(listed[0]["id"], newer.id)


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
        ticket = tickets.create("No pictures here")
        model, vision = session.pick_model(ticket, config.DEFAULTS)
        self.assertEqual(model, config.DEFAULT_TEXT_MODEL)
        self.assertFalse(vision)

    def test_a_screenshot_switches_to_the_vision_model(self):
        ticket = tickets.create("With a screenshot")
        session.attach(ticket, png(os.path.join(self.work, "shot.png")))
        model, vision = session.pick_model(ticket, config.DEFAULTS)
        self.assertEqual(model, config.DEFAULT_VISION_MODEL)
        self.assertTrue(vision)

    def test_the_prompt_carries_the_ticket_and_the_measurements(self):
        ticket = tickets.create("Wi-Fi drops", "Only on 5 GHz.")
        ticket.set_context({"system": {"platform": "Darwin-24", "hostname": "mac"},
                            "dns": {"servers": ["192.168.1.1"], "search": []}})
        messages = session.build_messages(ticket)
        self.assertEqual(messages[0]["role"], "system")
        text = messages[1]["content"]
        self.assertIn("Wi-Fi drops", text)
        self.assertIn("Only on 5 GHz", text)
        self.assertIn("192.168.1.1", text, "the gathered facts go in")

    def test_images_are_inlined_not_referenced(self):
        # The model server is a separate process: handing it a path would make it
        # read our files, and a URL would make somebody fetch one.
        ticket = tickets.create("Look at this")
        session.attach(ticket, png(os.path.join(self.work, "shot.png")))
        parts = session.build_messages(ticket)[1]["content"]
        images = [p for p in parts if p.get("type") == "image_url"]
        self.assertEqual(len(images), 1)
        self.assertTrue(images[0]["image_url"]["url"].startswith("data:image/"))

    def test_only_the_most_recent_images_are_sent(self):
        ticket = tickets.create("Many shots")
        for index in range(9):
            session.attach(ticket, png(os.path.join(self.work, "s%d.png" % index)))
        parts = session.build_messages(ticket, image_limit=4)[1]["content"]
        self.assertEqual(sum(1 for p in parts if p.get("type") == "image_url"), 4)

    def test_a_full_exchange_against_a_server(self):
        with StubModelServer(reply="Move to channel 149.") as server:
            ticket = tickets.create("Congested channel")
            streamed = []
            result = session.ask(ticket, "what now?", settings=self.settings(server),
                                 on_token=streamed.append, stream=True)
            self.assertEqual(result["answer"].strip(), "Move to channel 149.")
            self.assertTrue(streamed, "streaming delivers text as it arrives")
            self.assertEqual([m["role"] for m in ticket.messages],
                             ["user", "assistant"])
            sent = server.requests[-1]
            self.assertEqual(sent["model"], "llama3.1:8b")

    def test_the_conversation_is_replayed_so_it_has_memory(self):
        with StubModelServer(reply="Yes.") as server:
            ticket = tickets.create("Follow up")
            session.ask(ticket, "first question", settings=self.settings(server))
            session.ask(ticket, "second question", settings=self.settings(server))
            sent = server.requests[-1]["messages"]
            text = json.dumps(sent)
            self.assertIn("first question", text)
            self.assertIn("second question", text)

    def test_a_public_endpoint_is_refused_before_anything_is_sent(self):
        ticket = tickets.create("Should never be sent")
        settings = dict(config.DEFAULTS, endpoint="http://8.8.8.8:11434/v1")
        with self.assertRaises(llm.ModelError):
            session.ask(ticket, "hello", settings=settings)

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
