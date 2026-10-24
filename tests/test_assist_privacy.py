"""The no-egress guarantee, which is the reason Assist runs locally at all."""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from assist import privacy


class TestEndpointClassification(unittest.TestCase):
    def test_loopback_is_this_machine(self):
        for url in ("http://127.0.0.1:11434/v1", "http://localhost:11434/v1",
                    "http://[::1]:11434/v1"):
            ok, _reason = privacy.is_local_endpoint(url)
            self.assertTrue(ok, url)

    def test_a_public_endpoint_is_refused_and_told_why(self):
        ok, reason = privacy.is_local_endpoint("http://8.8.8.8:11434/v1")
        self.assertFalse(ok)
        self.assertIn("public", reason)
        # The refusal has to explain the point, not just say no.
        self.assertIn("tickets", reason)

    def test_the_lan_needs_asking_for(self):
        url = "http://192.168.1.50:11434/v1"
        ok, reason = privacy.is_local_endpoint(url)
        self.assertFalse(ok, "a box on the network is not this machine")
        self.assertIn("--allow-lan", reason)
        self.assertTrue(privacy.is_local_endpoint(url, allow_lan=True)[0])

    def test_a_name_that_does_not_resolve_is_not_assumed_safe(self):
        ok, reason = privacy.is_local_endpoint("http://nothing.invalid:1234/v1")
        self.assertFalse(ok)
        self.assertIn("does not resolve", reason)

    def test_describe_says_whether_anything_leaves(self):
        local = privacy.describe_egress("http://127.0.0.1:11434/v1")
        self.assertTrue(local["allowed"])
        self.assertFalse(local["leaves_machine"])
        lan = privacy.describe_egress("http://192.168.1.50:11434/v1", allow_lan=True)
        self.assertTrue(lan["allowed"])
        self.assertTrue(lan["leaves_machine"], "the LAN is still off this box")


class TestEgressGuard(unittest.TestCase):
    """The part that makes it a guarantee rather than a policy."""

    def test_it_blocks_a_connection_to_the_internet(self):
        with privacy.no_egress(allow=["127.0.0.1"]):
            sock = socket.socket()
            try:
                with self.assertRaises(privacy.EgressBlocked):
                    sock.connect(("1.1.1.1", 443))
            finally:
                sock.close()

    def test_connect_ex_is_guarded_too(self):
        # A library that avoids exceptions by using connect_ex must not slip past.
        with privacy.no_egress(allow=["127.0.0.1"]):
            sock = socket.socket()
            try:
                with self.assertRaises(privacy.EgressBlocked):
                    sock.connect_ex(("1.1.1.1", 443))
            finally:
                sock.close()

    def test_loopback_is_always_allowed(self):
        with privacy.no_egress(allow=[]):
            sock = socket.socket()
            sock.settimeout(1)
            try:
                sock.connect(("127.0.0.1", 1))
            except privacy.EgressBlocked:
                self.fail("the model server on this machine must be reachable")
            except OSError:
                pass                            # nothing listening, which is fine
            finally:
                sock.close()

    def test_the_named_model_host_is_allowed(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            with privacy.no_egress(allow=["127.0.0.1"]):
                sock = socket.socket()
                sock.settimeout(2)
                sock.connect(("127.0.0.1", port))
                sock.close()
        finally:
            listener.close()

    def test_the_guard_lifts_afterwards(self):
        original = socket.socket
        with privacy.no_egress(allow=["127.0.0.1"]):
            self.assertIsNot(socket.socket, original)
        self.assertIs(socket.socket, original,
                      "the guard must not leave the process crippled")

    def test_it_lifts_even_when_the_body_raises(self):
        original = socket.socket
        with self.assertRaises(ValueError):
            with privacy.no_egress(allow=["127.0.0.1"]):
                raise ValueError("something went wrong mid-session")
        self.assertIs(socket.socket, original)


if __name__ == "__main__":
    unittest.main()
