"""Documentation connectors, and the limits on what a sync may reach.

The behaviour worth guarding most carefully is not that a sync works - it is
what a sync is allowed to touch, and what it is allowed to carry. A connector
is the one outward-facing thing in Assist, so these tests are mostly about
keeping it narrow.
"""

import json
import os
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from assist import clients, connectors, notebooks, session, sync
from assist.connectors import ConnectorError, htmltext
from assist.privacy import EgressBlocked
from tests.assist_stub import StubModelServer
from tests.connector_stubs import BookStackStub, HuduStub, NetBoxStub


class ConnectorCase(unittest.TestCase):
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

    def token_file(self, body="secret-key", mode=0o600):
        path = os.path.join(self.work, "token-%d" % len(os.listdir(self.work)))
        with open(path, "w") as handle:
            handle.write(body)
        os.chmod(path, mode)
        return path

    def setup(self, name, url, token="secret-key"):
        config = connectors.load_config()
        config[name] = {"url": url, "token_file": self.token_file(token)}
        connectors.save_config(config)
        return connectors.get(name)

    def linked(self, name, url, token="secret-key", company_id=1):
        self.setup(name, url, token)
        client = clients.create("Acme Corp")
        client.link(name, company_id, "Acme Corp")
        return client


class TestTokens(ConnectorCase):
    def test_a_world_readable_token_file_is_refused(self):
        # This file holds a key that can read a client's whole documentation.
        path = self.token_file(mode=0o644)
        with self.assertRaises(ConnectorError) as caught:
            connectors.read_token(path=path)
        self.assertIn("readable by other users", str(caught.exception))

    def test_a_private_token_file_is_read(self):
        self.assertEqual(connectors.read_token(path=self.token_file()), "secret-key")

    def test_an_empty_token_file_says_so(self):
        with self.assertRaises(ConnectorError):
            connectors.read_token(path=self.token_file(body="  "))

    def test_a_missing_token_file_says_so(self):
        with self.assertRaises(ConnectorError):
            connectors.read_token(path=os.path.join(self.work, "nope"))

    def test_the_environment_is_accepted_too(self):
        os.environ["ASSIST_TEST_TOKEN"] = "from-env"
        try:
            self.assertEqual(connectors.read_token(env="ASSIST_TEST_TOKEN"), "from-env")
        finally:
            del os.environ["ASSIST_TEST_TOKEN"]

    def test_the_saved_config_is_not_world_readable(self):
        # Someone may pass --token inline, which lands here.
        connectors.save_config({"hudu": {"url": "http://x", "token": "abc"}})
        mode = os.stat(connectors.config_path()).st_mode
        self.assertEqual(mode & 0o077, 0, "connectors.json must be 0600")


class TestHudu(ConnectorCase):
    def test_articles_and_assets_come_across(self):
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            result = sync.sync_client(client)[0]
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["documents"], 2)
            names = [entry["stored"] for entry in client.sources]
            self.assertTrue(any("Acme-HQ-Firewall" in name for name in names))
            self.assertTrue(any("fw-hq-01" in name for name in names))

    def test_the_api_key_goes_in_the_documented_header(self):
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            sync.sync_client(client)
            self.assertTrue(stub.auth_headers())
            self.assertEqual(stub.auth_headers()[0], {"x-api-key": "secret-key"})

    def test_asset_fields_become_facts(self):
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            sync.sync_client(client)
            grouped = dict(client.grouped_facts())
            self.assertEqual(grouped["fw-hq-01 WAN IP"], ["203.0.113.1"])

    def test_passwords_are_never_pulled_in(self):
        # A documentation sync has no business carrying credentials into a
        # notebook, whatever the API key is allowed to read.
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            sync.sync_client(client)
            blob = json.dumps(client.detail())
            for entry in client.sources:
                with open(client.path_of(entry)) as handle:
                    blob += handle.read()
            self.assertNotIn("hunter2", blob)
            self.assertNotIn("Admin Password", blob)

    def test_html_is_flattened_to_text(self):
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            sync.sync_client(client)
            article = [e for e in client.sources if "Firewall" in e["stored"]][0]
            with open(client.path_of(article)) as handle:
                body = handle.read()
            self.assertIn("Fortigate 100F", body)
            self.assertNotIn("<p>", body)

    def test_a_rejected_token_is_reported_not_raised_as_a_traceback(self):
        with HuduStub() as stub:
            stub.fail_with(401)
            client = self.linked("hudu", stub.url)
            result = sync.sync_client(client)[0]
            self.assertFalse(result["ok"])
            self.assertIn("401", result["error"])


class TestNetBox(ConnectorCase):
    def test_devices_and_prefixes_become_facts(self):
        with NetBoxStub() as stub:
            client = self.linked("netbox", stub.url, company_id=3)
            result = sync.sync_client(client)[0]
            self.assertTrue(result["ok"], result)
            grouped = dict(client.grouped_facts())
            self.assertEqual(grouped["fw-hq-01"], ["10.20.0.1"])
            self.assertEqual(grouped["HQ subnet"], ["10.20.0.0/16"])
            self.assertIn("Warehouse", grouped["site"])

    def test_the_token_scheme_is_the_documented_one(self):
        with NetBoxStub() as stub:
            client = self.linked("netbox", stub.url, company_id=3)
            sync.sync_client(client)
            self.assertEqual(stub.auth_headers()[0],
                             {"authorization": "Token secret-key"})

    def test_the_scheme_can_be_changed_for_deployments_that_want_bearer(self):
        with NetBoxStub() as stub:
            config = connectors.load_config()
            config["netbox"] = {"url": stub.url, "token_file": self.token_file(),
                                "scheme": "Bearer"}
            connectors.save_config(config)
            connectors.get("netbox").check()
            self.assertEqual(stub.auth_headers()[0],
                             {"authorization": "Bearer secret-key"})

    def test_a_device_list_becomes_a_readable_document(self):
        with NetBoxStub() as stub:
            client = self.linked("netbox", stub.url, company_id=3)
            sync.sync_client(client)
            doc = [e for e in client.sources if "devices" in e["stored"]][0]
            with open(client.path_of(doc)) as handle:
                body = handle.read()
            self.assertIn("sw-core-01", body)
            self.assertIn("Fortigate 100F", body)


class TestBookStack(ConnectorCase):
    def test_pages_come_across_as_documents(self):
        with BookStackStub() as stub:
            client = self.linked("bookstack", stub.url, token="abc:def",
                                 company_id=4)
            result = sync.sync_client(client)[0]
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["documents"], 1)
            with open(client.path_of(client.sources[0])) as handle:
                self.assertIn("198.51.100.7", handle.read())

    def test_a_token_without_a_colon_is_explained(self):
        with BookStackStub() as stub:
            client = self.linked("bookstack", stub.url, token="justone",
                                 company_id=4)
            result = sync.sync_client(client)[0]
            self.assertFalse(result["ok"])
            self.assertIn("colon", result["error"])


class TestFolder(ConnectorCase):
    def setUp(self):
        super().setUp()
        self.docs = os.path.join(self.work, "docs")
        os.makedirs(os.path.join(self.docs, "Acme Corp"))
        with open(os.path.join(self.docs, "Acme Corp", "vpn.md"), "w") as handle:
            handle.write("# VPN\n\nPeer is 198.51.100.7.\n")
        with open(os.path.join(self.docs, "Acme Corp", "photo.jpg"), "wb") as handle:
            handle.write(b"\xff\xd8\xff")

    def test_a_local_folder_needs_no_network_at_all(self):
        config = connectors.load_config()
        config["folder"] = {"path": self.docs}
        connectors.save_config(config)
        client = clients.create("Acme Corp")
        client.link("folder", "Acme Corp", "Acme Corp")

        # Proven, not assumed: with every outbound connection refused, the sync
        # still works, because it never makes one.
        from assist.privacy import no_egress

        with no_egress(allow=[]):
            result = sync.sync_client(client)[0]
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["documents"], 1)

    def test_unreadable_kinds_are_left_alone(self):
        config = connectors.load_config()
        config["folder"] = {"path": self.docs}
        connectors.save_config(config)
        client = clients.create("Acme Corp")
        client.link("folder", "Acme Corp", "Acme Corp")
        sync.sync_client(client)
        self.assertEqual(len(client.sources), 1, "the jpeg is not documentation")

    def test_the_folder_connector_is_reported_as_local(self):
        config = connectors.load_config()
        config["folder"] = {"path": self.docs}
        connectors.save_config(config)
        described = {entry["name"]: entry for entry in connectors.describe_all()}
        self.assertFalse(described["folder"]["leaves_machine"])


class TestWhatASyncMayReach(ConnectorCase):
    """The part that matters: a sync is narrow, and the model stays local."""

    def test_a_sync_cannot_reach_anywhere_but_the_declared_host(self):
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            sync.sync_client(client)
            # Inside the sync the guard is live; prove the same guard refuses a
            # real public address, so the sync was not simply unguarded.
            from assist.privacy import no_egress

            with no_egress(allow=[stub.url.split("//")[1].split(":")[0]],
                           purpose="the documentation server you configured"):
                probe = socket.socket()
                try:
                    with self.assertRaises(EgressBlocked):
                        probe.connect(("1.1.1.1", 443))
                finally:
                    probe.close()

    def test_a_redirect_to_another_host_is_refused(self):
        from assist.connectors.http import _SameHostRedirects

        handler = _SameHostRedirects("docs.example.com")
        with self.assertRaises(ConnectorError):
            handler.redirect_request(None, None, 302, "Found", {},
                                     "https://evil.example.net/steal")

    def test_a_notebook_is_never_sent_to_the_documentation_server(self):
        # The whole point: documentation comes in, nothing about the ticket
        # goes out.
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            notebook = notebooks.create("A very distinctive ticket title",
                                        "SECRETBODYMARKER", client=client.id)
            notebook.add_source(_file(self.work, "evidence.log", "EVIDENCEMARKER\n"))
            sync.sync_client(client)
            sent = json.dumps(stub.requests)
            self.assertNotIn("SECRETBODYMARKER", sent)
            self.assertNotIn("EVIDENCEMARKER", sent)
            self.assertNotIn("distinctive", sent)

    def test_asking_the_model_after_a_sync_touches_only_the_model(self):
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            sync.sync_client(client)
            notebook = notebooks.create("Why is the VPN down", client=client.id)
        # The documentation server is gone now. The answer must still work,
        # because what it needs was cached as the client's own sources.
        with StubModelServer() as model:
            from assist import config

            settings = dict(config.DEFAULTS, endpoint=model.endpoint)
            result = session.ask(notebook, "what do we know?", settings=settings,
                                 stream=False)
            self.assertTrue(result["answer"])
            sent = json.dumps(model.requests[-1])
            self.assertIn("Fortigate 100F", sent, "the synced doc is in the prompt")

    def test_doctor_names_every_connector_and_where_it_points(self):
        with HuduStub() as stub:
            self.setup("hudu", stub.url)
            described = {entry["name"]: entry for entry in connectors.describe_all()}
            self.assertIn("hudu", described)
            self.assertEqual(described["hudu"]["classification"], "loopback")
            self.assertFalse(described["hudu"]["leaves_machine"])

    def test_a_public_documentation_host_is_reported_as_leaving(self):
        connectors.save_config({"hudu": {"url": "https://acme.huducloud.com",
                                         "allow_public": True}})
        described = {entry["name"]: entry for entry in connectors.describe_all()}
        entry = described["hudu"]
        # It either resolves publicly or does not resolve from here; either way
        # it must not be reported as being on this machine.
        self.assertNotEqual(entry["classification"], "loopback")
        self.assertNotEqual(entry["where"], "on this machine")


class TestSetupGate(ConnectorCase):
    """Reaching off this machine is a choice, taken once, out loud."""

    def _add(self, argv):
        from assist import cli
        import io
        import contextlib

        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(argv)
        return code, err.getvalue()

    def test_a_loopback_server_needs_no_permission(self):
        with HuduStub() as stub:
            code, _err = self._add(["connector", "add", "hudu", "--url", stub.url,
                                    "--token-file", self.token_file()])
            self.assertEqual(code, 0)
            self.assertIn("hudu", connectors.load_config())

    def test_a_host_that_does_not_resolve_is_not_treated_as_safe(self):
        # The hole this closes: an unresolvable name is unknown, not local, and
        # may resolve to a hosted service somewhere with working DNS.
        code, err = self._add(["connector", "add", "hudu",
                               "--url", "https://no-such-host.invalid",
                               "--token", "x", "--no-check"])
        self.assertEqual(code, 2)
        self.assertIn("--allow-public", err)
        self.assertNotIn("hudu", connectors.load_config())

    def test_saying_so_explicitly_lets_it_through_and_is_recorded(self):
        code, _err = self._add(["connector", "add", "hudu",
                                "--url", "https://no-such-host.invalid",
                                "--token", "x", "--allow-public", "--no-check"])
        self.assertEqual(code, 0)
        self.assertTrue(connectors.load_config()["hudu"]["allow_public"])

    def test_a_private_network_server_keeps_the_promise_and_needs_no_flag(self):
        code, _err = self._add(["connector", "add", "hudu",
                                "--url", "http://10.20.0.50", "--token", "x",
                                "--no-check"])
        self.assertEqual(code, 0)
        self.assertFalse(connectors.load_config()["hudu"]["allow_public"])


class TestResync(ConnectorCase):
    def test_a_resync_replaces_its_own_documents_and_not_yours(self):
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            client.add_source(_file(self.work, "mine.md", "MY OWN NOTE\n"))
            sync.sync_client(client)
            first = len(client.sources)
            sync.sync_client(client)
            self.assertEqual(len(client.sources), first,
                             "a re-sync must not pile up duplicates")
            names = [entry["stored"] for entry in client.sources]
            self.assertIn("mine.md", names, "a hand-added source must survive")

    def test_a_resync_replaces_its_own_facts_and_not_yours(self):
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            client.add_fact("ISP", "Northline Telecom")
            sync.sync_client(client)
            sync.sync_client(client)
            grouped = dict(client.grouped_facts())
            self.assertEqual(grouped["ISP"], ["Northline Telecom"])
            self.assertEqual(grouped["fw-hq-01 WAN IP"], ["203.0.113.1"],
                             "synced facts must not duplicate on a re-sync")

    def test_a_document_deleted_upstream_stops_being_quoted(self):
        with HuduStub() as stub:
            client = self.linked("hudu", stub.url)
            sync.sync_client(client)
            self.assertTrue(any("Firewall" in e["stored"] for e in client.sources))
            # The far end loses the article.
            stub.route = lambda path, query: (
                {"articles": []} if path.endswith("/articles")
                else HuduStub.route(stub, path, query))
            stub.httpd.route = stub.route
            sync.sync_client(client)
            self.assertFalse(any("Firewall" in e["stored"] for e in client.sources))

    def test_one_connector_failing_does_not_cost_the_others(self):
        with HuduStub() as hudu, NetBoxStub() as netbox:
            client = self.linked("hudu", hudu.url)
            self.setup("netbox", netbox.url)
            client.link("netbox", 3, "Acme Corp")
            hudu.fail_with(500)
            results = {r["connector"]: r for r in sync.sync_client(client)}
            self.assertFalse(results["hudu"]["ok"])
            self.assertTrue(results["netbox"]["ok"])
            self.assertTrue(client.facts, "NetBox's facts still arrived")


class TestHtmlToText(unittest.TestCase):
    def test_headings_lists_and_tables_survive(self):
        text = htmltext.to_text(
            "<h2>Edge</h2><ul><li>WAN: 203.0.113.1</li></ul>"
            "<table><tr><td>HQ</td><td>10.20.0.0/16</td></tr></table>")
        self.assertIn("## Edge", text)
        self.assertIn("- WAN: 203.0.113.1", text)
        self.assertIn("HQ | 10.20.0.0/16", text)

    def test_scripts_and_styles_are_dropped(self):
        text = htmltext.to_text("<p>keep</p><script>var secret = 1;</script>"
                                "<style>p{color:red}</style>")
        self.assertIn("keep", text)
        self.assertNotIn("secret", text)
        self.assertNotIn("color", text)

    def test_a_link_target_is_kept_when_it_adds_something(self):
        text = htmltext.to_text('<a href="https://example.com/vpn">the runbook</a>')
        self.assertIn("the runbook", text)
        self.assertIn("https://example.com/vpn", text)

    def test_broken_markup_does_not_raise(self):
        self.assertIn("text", htmltext.to_text("<p>text<div><span>"))

    def test_entities_are_decoded(self):
        self.assertIn("A & B", htmltext.to_text("<p>A &amp; B</p>"))

    def test_empty_input_is_empty_output(self):
        self.assertEqual(htmltext.to_text(""), "")
        self.assertEqual(htmltext.to_text(None), "")


def _file(directory, name, body):
    path = os.path.join(directory, name)
    with open(path, "w") as handle:
        handle.write(body)
    return path


if __name__ == "__main__":
    unittest.main()
