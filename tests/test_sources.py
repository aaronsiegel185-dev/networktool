"""Turning files into something a model can actually read.

The pcap tests build real captures with Network Tool's own writer rather than
using fixtures, so what is tested is the path a user's capture takes.
"""

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from assist import notebooks, sources


def write_pcap(path, packets):
    """A real pcap, through Network Tool's writer."""
    from nettool.pcap import PcapWriter

    with PcapWriter(path, linktype=1) as writer:
        for index, data in enumerate(packets):
            writer.write(data, 1700000000.0 + index * 0.01)
    return path


def tcp_packet(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=443,
               flags=0x18, payload=b"hello"):
    """Ethernet + IPv4 + TCP, enough for the analyzer to count it."""
    def ip(text):
        return bytes(int(part) for part in text.split("."))

    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 8192, 0, 0)
    tcp += payload
    total = 20 + len(tcp)
    header = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0) + ip(src) + ip(dst)
    ethernet = (b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"
                + b"\x08\x00")
    return ethernet + header + tcp


class SourceCase(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.home = tempfile.mkdtemp()
        self._saved = os.environ.get("TOOLBOX_HOME")
        os.environ["TOOLBOX_HOME"] = self.home

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("TOOLBOX_HOME", None)
        else:
            os.environ["TOOLBOX_HOME"] = self._saved

    def file(self, name, body):
        path = os.path.join(self.work, name)
        with open(path, "w") as handle:
            handle.write(body)
        return path


class TestClassify(SourceCase):
    def test_a_capture_is_known_by_its_magic_not_its_name(self):
        path = write_pcap(os.path.join(self.work, "no-extension"), [tcp_packet()])
        self.assertEqual(sources.classify(path), "capture")

    def test_a_log_and_a_config_are_told_apart(self):
        self.assertEqual(sources.classify(self.file("x.log", "boot\n")), "log")
        self.assertEqual(sources.classify(self.file("x.conf", "a=1\n")), "config")
        self.assertEqual(sources.classify(self.file("x.json", "{}")), "json")
        self.assertEqual(sources.classify(self.file("x.csv", "a,b\n")), "table")

    def test_text_without_a_known_extension_is_still_read(self):
        path = self.file("README", "this is prose\n")
        self.assertEqual(sources.classify(path), "text")

    def test_binary_is_not_claimed_to_be_text(self):
        path = os.path.join(self.work, "blob.bin")
        with open(path, "wb") as handle:
            handle.write(bytes(range(256)))
        self.assertEqual(sources.classify(path), "other")

    def test_a_missing_file_says_so(self):
        with self.assertRaises(sources.SourceError):
            sources.classify(os.path.join(self.work, "nope"))


class TestCaptureDigest(SourceCase):
    def test_a_capture_becomes_prose_with_real_numbers(self):
        path = write_pcap(os.path.join(self.work, "c.pcap"),
                          [tcp_packet() for _ in range(12)])
        text, note = sources.digest(path)
        self.assertIn("PACKET CAPTURE", text)
        self.assertIn("12 packets", text)
        self.assertIn("12 packets", note)
        # The conversation is named, so the model can cite an address.
        self.assertIn("10.0.0.1", text)

    def test_the_analyzers_findings_are_carried_through(self):
        # A pile of SYNs with no answer is something the analyzer flags, and it
        # is exactly the sort of thing the model should be told rather than
        # left to infer from a packet count.
        packets = [tcp_packet(sport=1000 + n, flags=0x02, payload=b"")
                   for n in range(30)]
        text, _note = sources.digest(write_pcap(
            os.path.join(self.work, "syn.pcap"), packets))
        self.assertIn("What the analyzer flagged:", text)
        self.assertIn("no SYN/ACK", text)

    def test_one_level_of_conversation_not_three(self):
        # The analyzer tracks ethernet, IP and transport separately. Listing all
        # three says the same traffic three times and wastes the context.
        text, _note = sources.digest(write_pcap(
            os.path.join(self.work, "c.pcap"), [tcp_packet() for _ in range(5)]))
        conversations = text.split("Busiest conversations:")[1].split("\n\n")[0]
        self.assertNotIn("02:00:00:00:00:01", conversations,
                         "MAC-level conversations duplicate the IP ones")

    def test_an_unreadable_capture_is_reported_not_raised(self):
        # A truncated capture must leave the notebook usable rather than
        # breaking every later question.
        path = os.path.join(self.work, "bad.pcap")
        with open(path, "wb") as handle:
            handle.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 8)
        text, note = sources.digest(path, "capture")
        self.assertEqual(text, "")
        self.assertIn("could not be read", note)


class TestTextDigest(SourceCase):
    def test_a_short_file_is_included_whole(self):
        path = self.file("small.log", "one\ntwo\nthree\n")
        text, note = sources.digest(path)
        self.assertIn("one", text)
        self.assertIn("three", text)
        self.assertEqual(note, "3 lines")

    def test_a_long_file_keeps_its_tail(self):
        # The last lines of a log are usually where the failure is. Trimming
        # from the end would throw away the only part worth reading.
        lines = ["line %d padded %s" % (n, "x" * 200) for n in range(4000)]
        lines.append("THE FAILURE IS HERE")
        path = self.file("big.log", "\n".join(lines) + "\n")
        text, note = sources.digest(path)
        self.assertEqual(note, "4001 lines")
        self.assertIn("THE FAILURE IS HERE", text)
        self.assertIn("line 0 padded", text)
        self.assertIn("omitted from the middle", text)
        self.assertLessEqual(len(text), sources.MAX_DIGEST)

    def test_a_single_enormous_line_cannot_blow_the_budget(self):
        path = self.file("one.log", "x" * 500000 + "\n")
        text, _note = sources.digest(path)
        self.assertLessEqual(len(text), sources.MAX_DIGEST)

    def test_invalid_utf8_does_not_raise(self):
        path = os.path.join(self.work, "mixed.log")
        with open(path, "wb") as handle:
            handle.write(b"fine\n\xff\xfe broken\nalso fine\n")
        text, _note = sources.digest(path, "log")
        self.assertIn("also fine", text)


class TestSourcesInANotebook(SourceCase):
    def test_a_capture_added_to_a_notebook_carries_its_rendering(self):
        notebook = notebooks.create("With a capture")
        path = write_pcap(os.path.join(self.work, "c.pcap"),
                          [tcp_packet() for _ in range(7)])
        entry = notebook.add_source(path)
        self.assertEqual(entry["kind"], "capture")
        self.assertIn("7 packets", entry["digest"])
        # Reloading from disk must give the same rendering, not re-derive it.
        reloaded = notebooks.load(notebook.id)
        self.assertIn("7 packets", reloaded.sources[0]["digest"])

    def test_the_original_capture_is_kept_beside_its_rendering(self):
        # A claim the model makes about a capture has to be checkable against
        # the capture itself.
        notebook = notebooks.create("Both kept")
        path = write_pcap(os.path.join(self.work, "c.pcap"), [tcp_packet()])
        entry = notebook.add_source(path)
        stored = notebook.path_of(entry)
        self.assertTrue(os.path.exists(stored))
        with open(stored, "rb") as handle:
            self.assertTrue(handle.read(4).startswith(b"\xd4\xc3\xb2\xa1"))

    def test_sources_fit_a_budget_and_say_what_was_left_out(self):
        from assist import session

        notebook = notebooks.create("Too much")
        for index in range(12):
            notebook.add_source(self.file(
                "big%02d.log" % index,
                "\n".join("filler %d" % n for n in range(2000))))
        blocks, omitted = session.source_blocks(notebook)
        self.assertTrue(omitted, "something should not have fitted")
        self.assertLessEqual(sum(len(block) for block in blocks),
                             session.SOURCE_BUDGET)
        # The newest source is the one just added, and is the one kept.
        self.assertIn("big11.log", "".join(blocks))

    def test_what_did_not_fit_is_named_in_the_prompt(self):
        from assist import session

        notebook = notebooks.create("Too much")
        for index in range(12):
            notebook.add_source(self.file(
                "big%02d.log" % index,
                "\n".join("filler %d" % n for n in range(2000))))
        messages = session.build_messages(notebook)
        prompt = messages[1]["content"]
        if isinstance(prompt, list):
            prompt = " ".join(part.get("text", "") for part in prompt)
        self.assertIn("Not shown here, for space", prompt)

    def test_switching_a_source_off_removes_it_from_the_prompt(self):
        from assist import session

        notebook = notebooks.create("Selective")
        notebook.add_source(self.file("keep.log", "KEEPME\n"))
        notebook.add_source(self.file("drop.log", "DROPME\n"))
        notebook.set_source_enabled("drop.log", False)
        messages = session.build_messages(notebook)
        prompt = messages[1]["content"]
        if isinstance(prompt, list):
            prompt = " ".join(part.get("text", "") for part in prompt)
        self.assertIn("KEEPME", prompt)
        self.assertNotIn("DROPME", prompt)
        self.assertNotIn("drop.log", prompt)


if __name__ == "__main__":
    unittest.main()
