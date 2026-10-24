"""Clients: grouping notebooks, and the context that outlives any one ticket."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from assist import clients, config, notebooks, session
from assist.store import StoreError
from tests.assist_stub import StubModelServer


class ClientCase(unittest.TestCase):
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

    def file(self, name, body):
        path = os.path.join(self.work, name)
        with open(path, "w") as handle:
            handle.write(body)
        return path

    def acme(self):
        client = clients.create("Acme Corp", notes="Two sites, joined by IPsec.")
        client.add_fact("firewall", "203.0.113.1")
        client.add_fact("firewall", "203.0.113.2")
        client.add_fact("ISP", "Northline Telecom")
        return client


class TestFacts(ClientCase):
    def test_one_label_can_hold_several_values(self):
        # Most of what someone writes down is plural: two firewalls, six
        # servers. A label that only held one value would lose half of it.
        client = self.acme()
        grouped = dict(client.grouped_facts())
        self.assertEqual(grouped["firewall"], ["203.0.113.1", "203.0.113.2"])
        self.assertEqual(grouped["ISP"], ["Northline Telecom"])

    def test_labels_keep_the_order_they_were_written_in(self):
        client = self.acme()
        self.assertEqual([label for label, _ in client.grouped_facts()],
                         ["firewall", "ISP"])

    def test_an_exact_repeat_is_not_stored_twice(self):
        # Re-running a setup script should not leave the same address in the
        # prompt four times.
        client = self.acme()
        client.add_fact("firewall", "203.0.113.1")
        self.assertEqual(len(client.facts), 3)

    def test_forgetting_a_label_drops_all_of_its_values(self):
        client = self.acme()
        self.assertEqual(client.forget("firewall"), 2)
        self.assertNotIn("firewall", dict(client.grouped_facts()))

    def test_forgetting_one_value_leaves_the_others(self):
        client = self.acme()
        self.assertEqual(client.forget("firewall", "203.0.113.1"), 1)
        self.assertEqual(dict(client.grouped_facts())["firewall"],
                         ["203.0.113.2"])

    def test_a_fact_needs_a_label(self):
        client = self.acme()
        with self.assertRaises(clients.ClientError):
            client.add_fact("", "nothing")

    def test_facts_survive_a_round_trip(self):
        client = self.acme()
        reloaded = clients.load(client.id)
        self.assertEqual(len(reloaded.facts), 3)
        self.assertEqual(reloaded.notes, "Two sites, joined by IPsec.")


class TestResolving(ClientCase):
    def test_a_client_is_found_by_id_or_name_or_prefix(self):
        self.acme()
        for text in ("acme-corp", "Acme Corp", "acme", "ACME"):
            found = clients.resolve(text)
            self.assertIsNotNone(found, text)
            self.assertEqual(found.id, "acme-corp")

    def test_an_ambiguous_prefix_is_refused_rather_than_guessed(self):
        clients.create("Northwind Logistics")
        clients.create("Northline Telecom")
        with self.assertRaises(clients.ClientError):
            clients.resolve("north")

    def test_an_unknown_name_is_none_not_an_error(self):
        self.assertIsNone(clients.resolve("nobody"))

    def test_two_clients_cannot_share_an_id(self):
        clients.create("Acme Corp")
        with self.assertRaises(clients.ClientError):
            clients.create("acme corp")


class TestGrouping(ClientCase):
    def test_notebooks_are_filed_and_listed_by_client(self):
        client = self.acme()
        notebooks.create("Wi-Fi drops", client=client.id)
        notebooks.create("VPN flapping", client=client.id)
        notebooks.create("Something else")
        self.assertEqual(len(notebooks.listing(client=client.id)), 2)
        self.assertEqual(len(notebooks.listing()), 3)

    def test_a_listing_row_carries_the_client_name_not_just_its_id(self):
        client = self.acme()
        notebooks.create("Wi-Fi drops", client=client.id)
        row = notebooks.listing()[0]
        self.assertEqual(row["client"], "acme-corp")
        self.assertEqual(row["client_name"], "Acme Corp")

    def test_an_unfiled_notebook_has_an_empty_client(self):
        notebooks.create("Mine")
        row = notebooks.listing()[0]
        self.assertEqual(row["client"], "")
        self.assertEqual(row["client_name"], "")

    def test_a_notebook_can_be_moved_between_clients_and_out(self):
        first = self.acme()
        second = clients.create("Other Ltd")
        notebook = notebooks.create("Wi-Fi drops", client=first.id)
        notebook.set_client(second.id)
        self.assertEqual(notebooks.load(notebook.id).client_id, "other-ltd")
        notebook.set_client(None)
        self.assertIsNone(notebooks.load(notebook.id).client_id)

    def test_the_client_count_is_reported(self):
        client = self.acme()
        notebooks.create("One", client=client.id)
        notebooks.create("Two", client=client.id)
        entry = clients.listing()[0]
        self.assertEqual(entry["notebooks"], 2)
        self.assertEqual(entry["facts"], 3)

    def test_deleting_a_client_keeps_its_notebooks(self):
        # A year of someone's tickets must not go with the client record.
        client = self.acme()
        notebooks.create("Wi-Fi drops", client=client.id)
        orphaned = clients.remove(client.id)
        self.assertEqual(orphaned, 1)
        remaining = notebooks.listing()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["client"], "")

    def test_a_notebook_whose_client_vanished_still_opens(self):
        # Losing standing context is not a reason to make a notebook unusable.
        client = self.acme()
        notebook = notebooks.create("Wi-Fi drops", client=client.id)
        import shutil

        shutil.rmtree(client.directory)
        reloaded = notebooks.load(notebook.id)
        self.assertIsNone(reloaded.client())
        messages = session.build_messages(reloaded)
        self.assertTrue(messages)


class TestStandingContext(ClientCase):
    def test_the_facts_reach_the_prompt(self):
        client = self.acme()
        notebook = notebooks.create("VPN flapping", client=client.id)
        prompt = _user_text(session.build_messages(notebook))
        self.assertIn("CLIENT: Acme Corp", prompt)
        self.assertIn("203.0.113.1, 203.0.113.2", prompt)
        self.assertIn("Northline Telecom", prompt)
        self.assertIn("Two sites, joined by IPsec.", prompt)

    def test_standing_context_is_marked_as_background_not_as_a_reading(self):
        # The model must not report a firewall address as something it
        # measured this afternoon.
        client = self.acme()
        notebook = notebooks.create("VPN flapping", client=client.id)
        prompt = _user_text(session.build_messages(notebook))
        self.assertIn("not measured today", prompt)

    def test_a_client_with_nothing_written_down_adds_no_noise(self):
        client = clients.create("Bare Ltd")
        notebook = notebooks.create("Something", client=client.id)
        prompt = _user_text(session.build_messages(notebook))
        self.assertIn("CLIENT: Bare Ltd", prompt)
        self.assertNotIn("STANDING CONTEXT", prompt)

    def test_an_unfiled_notebook_carries_no_client_block(self):
        self.acme()
        notebook = notebooks.create("Mine, not theirs")
        prompt = _user_text(session.build_messages(notebook))
        self.assertNotIn("STANDING", prompt)
        self.assertNotIn("Acme", prompt)

    def test_client_reference_files_are_rendered_and_labelled(self):
        client = self.acme()
        client.add_source(self.file("fw.conf", "interface outside\n  ip 203.0.113.1\n"))
        notebook = notebooks.create("VPN flapping", client=client.id)
        prompt = _user_text(session.build_messages(notebook))
        self.assertIn("STANDING REFERENCE, kept on file for Acme Corp", prompt)
        self.assertIn("interface outside", prompt)

    def test_a_client_source_can_be_switched_off(self):
        client = self.acme()
        client.add_source(self.file("fw.conf", "SECRETMARKER\n"))
        client.set_source_enabled("fw.conf", False)
        notebook = notebooks.create("VPN flapping", client=client.id)
        prompt = _user_text(session.build_messages(notebook))
        self.assertNotIn("SECRETMARKER", prompt)

    def test_client_reference_cannot_crowd_out_the_ticket(self):
        # Background is useful, but never at the cost of the capture someone
        # just took. The client gets its own slice of the budget.
        client = self.acme()
        for index in range(12):
            client.add_source(self.file(
                "ref%02d.log" % index,
                "\n".join("client filler %d" % n for n in range(2000))))
        notebook = notebooks.create("VPN flapping", client=client.id)
        notebook.add_source(self.file("evidence.log", "THE EVIDENCE\n"))
        prompt = _user_text(session.build_messages(notebook))
        self.assertIn("THE EVIDENCE", prompt)
        client_text, omitted = session.client_blocks(client)
        self.assertTrue(omitted, "some client reference should not have fitted")
        self.assertLessEqual(sum(len(block) for block in client_text),
                             session.CLIENT_SOURCE_BUDGET)

    def test_the_client_comes_before_the_evidence(self):
        # It is the frame you read the evidence through, not another exhibit.
        client = self.acme()
        notebook = notebooks.create("VPN flapping", client=client.id)
        notebook.add_source(self.file("evidence.log", "THE EVIDENCE\n"))
        prompt = _user_text(session.build_messages(notebook))
        self.assertLess(prompt.index("STANDING CONTEXT"),
                        prompt.index("THE EVIDENCE"))

    def test_a_client_screenshot_switches_on_the_vision_model(self):
        from tests.test_assist import png

        client = self.acme()
        client.add_source(png(os.path.join(self.work, "rack.png")))
        notebook = notebooks.create("VPN flapping", client=client.id)
        settings = dict(config.DEFAULTS)
        _model, vision = session.pick_model(notebook, settings)
        self.assertTrue(vision, "a client's images are images too")

    def test_a_full_exchange_sends_the_client_context(self):
        client = self.acme()
        notebook = notebooks.create("VPN flapping", client=client.id)
        with StubModelServer() as stub:
            settings = dict(config.DEFAULTS, endpoint=stub.endpoint)
            session.ask(notebook, "why is it flapping?", settings=settings,
                        stream=False)
            sent = json.dumps(stub.requests[-1])
            self.assertIn("203.0.113.1", sent)
            self.assertIn("Acme Corp", sent)


def _user_text(messages):
    """The first user turn as plain text, images or not."""
    content = messages[1]["content"]
    if isinstance(content, list):
        return "\n".join(part.get("text", "") for part in content)
    return content


if __name__ == "__main__":
    unittest.main()
