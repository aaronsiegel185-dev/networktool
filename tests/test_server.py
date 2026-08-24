"""The local API the iOS app drives, exercised over a real socket."""

import io
import json
import os
import struct
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import server


def sample_pcap():
    """A one-packet capture holding a real ARP request."""
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frame = (b"\xff" * 6 + b"\x3c\x22\xfb\x11\x22\x33" + b"\x08\x06"
             + b"\x00\x01\x08\x00\x06\x04\x00\x01"
             + b"\x3c\x22\xfb\x11\x22\x33" + bytes([192, 168, 1, 42])
             + b"\x00" * 6 + bytes([192, 168, 1, 1]))
    return header + struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp()
        with open(os.path.join(cls.directory, "sample.pcap"), "wb") as fh:
            fh.write(sample_pcap())
        cls.httpd = server.serve(host="127.0.0.1", port=0, token="secret",
                                 capture_dir=cls.directory, announce=False,
                                 sink=io.StringIO())
        cls.base = "http://127.0.0.1:%d/api/v1/" % cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        server.shutdown(cls.httpd)

    def get(self, path, token="secret", raw=False):
        request = urllib.request.Request(self.base + path)
        if token:
            request.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read()
                return response.status, (body if raw else json.loads(body))
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                return exc.code, json.loads(body)
            except ValueError:
                return exc.code, body

    # --- pairing ---------------------------------------------------------

    def test_hello_is_open_so_the_app_can_show_what_it_found(self):
        status, body = self.get("hello", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(body["service"], "nettool")
        self.assertEqual(body["api"], "v1")
        self.assertIn("capabilities", body)

    def test_everything_else_needs_the_token(self):
        for path in ("iface", "routes", "captures", "ping?host=127.0.0.1"):
            status, body = self.get(path, token=None)
            self.assertEqual(status, 401, path)
            self.assertIn("token", body["error"])

    def test_a_wrong_token_is_refused(self):
        self.assertEqual(self.get("iface", token="guess")[0], 401)

    def test_the_token_may_also_come_as_a_query_parameter(self):
        # QR codes and pairing links carry it that way.
        status, _ = self.get("iface?token=secret", token=None)
        self.assertEqual(status, 200)

    # --- reports ---------------------------------------------------------

    def test_interfaces_and_routes(self):
        status, body = self.get("iface")
        self.assertEqual(status, 200)
        self.assertTrue(body["interfaces"])
        self.assertIn("name", body["interfaces"][0])
        self.assertEqual(self.get("routes")[0], 200)

    def test_ping_reports_loss_and_timing(self):
        status, body = self.get("ping?host=127.0.0.1&count=2")
        self.assertEqual(status, 200)
        self.assertEqual(body["sent"], 2)
        self.assertIn("loss_pct", body)
        # rtts is dropped: the app wants the summary, not every sample.
        self.assertNotIn("rtts", body)

    def test_captures_are_listed_with_their_size(self):
        status, body = self.get("captures")
        self.assertEqual(status, 200)
        names = [entry["name"] for entry in body["captures"]]
        self.assertIn("sample.pcap", names)

    def test_a_capture_downloads_as_bytes(self):
        status, body = self.get("download?file=sample.pcap", raw=True)
        self.assertEqual(status, 200)
        self.assertEqual(body, sample_pcap())

    def test_analysis_runs_over_a_named_capture(self):
        status, body = self.get("analyze?file=sample.pcap")
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], 1)
        self.assertIn("conversations", body)

    # --- refusals --------------------------------------------------------

    def test_a_path_cannot_escape_the_capture_directory(self):
        for attempt in ("../../etc/passwd", "/etc/passwd", "sub/dir.pcap", ".hidden"):
            status, body = self.get("download?file=%s" % attempt, raw=True)
            self.assertEqual(status, 400, attempt)
        self.assertEqual(self.get("analyze?file=../../etc/passwd")[0], 400)

    def test_a_host_is_checked_before_it_reaches_a_command(self):
        for attempt in ("; rm -rf /", "$(whoami)", "a b", "`id`"):
            status, body = self.get("ping?host=%s&count=1"
                                    % urllib.parse.quote(attempt))
            self.assertEqual(status, 400, attempt)
            self.assertIn("hostname", body["error"])

    def test_an_interface_name_is_checked_too(self):
        status, body = self.get("wifi/scan?interface=%s"
                                % urllib.parse.quote("en0; reboot"))
        self.assertEqual(status, 400)

    def test_numbers_are_clamped_rather_than_trusted(self):
        # A capture of a million seconds would hold the socket forever.
        status, body = self.get("ping?host=127.0.0.1&count=99999")
        self.assertEqual(status, 200)
        self.assertLessEqual(body["sent"], 30)

    def test_unknown_endpoints_say_what_exists(self):
        status, body = self.get("nonsense")
        self.assertEqual(status, 404)
        self.assertIn("iface", body["endpoints"])

    def test_a_path_outside_the_api_is_not_served(self):
        status, body = self.get("../../etc/passwd", raw=True)
        self.assertIn(status, (400, 404))


class TestPairingLink(unittest.TestCase):
    def test_localhost_binding_says_a_phone_cannot_reach_it(self):
        # A diagnostics API that binds every interface by surprise is a gift to
        # whoever else is on the coffee shop wifi - so localhost is the default,
        # and the output has to say why nothing can connect yet.
        out = io.StringIO()
        httpd = server.serve(host="127.0.0.1", port=0, token="x", announce=False,
                             sink=out)
        try:
            printed = out.getvalue()
            self.assertIn("localhost", printed)
            self.assertIn("--lan", printed)
            self.assertIn("nettool://127.0.0.1", printed)
        finally:
            server.shutdown(httpd)

    def test_lan_mode_leads_with_the_pairing_link(self):
        out = io.StringIO()
        httpd = server.serve(host="0.0.0.0", port=0, token="SAMPLE", announce=False,
                             sink=out)
        try:
            printed = out.getvalue()
            self.assertIn("To pair", printed)
            self.assertIn("?token=SAMPLE", printed)
            # The scheme is what makes the link openable rather than typed.
            self.assertIn("nettool://", printed)
        finally:
            server.shutdown(httpd)

    def test_a_token_is_generated_when_none_is_given(self):
        out = io.StringIO()
        httpd = server.serve(host="127.0.0.1", port=0, announce=False, sink=out)
        try:
            self.assertGreater(len(httpd.pairing_token), 20)
            self.assertIn(httpd.pairing_token, out.getvalue())
        finally:
            server.shutdown(httpd)


if __name__ == "__main__":
    unittest.main()
