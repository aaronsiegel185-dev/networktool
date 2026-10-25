"""NetBox: the open-source source of truth for what is actually on a network.

This is the connector that pays off fastest for network work. The facts someone
would otherwise type by hand - device names, management addresses, prefixes per
site, the VLANs - are already in NetBox, maintained, and correct. Pulling them
in as a client's standing context means the model is reasoning about the real
topology rather than about what someone remembered to write down.

NetBox authenticates with `Authorization: Token <key>`. The scheme is
configurable because some deployments and some versions expect `Bearer`.
List endpoints paginate by handing back the URL of the next page.
"""

from .. import connectors
from .http import ConnectorError

# How many of each kind to bring back. A large NetBox holds far more than a
# prompt can, and a client's standing context is meant to be the shape of their
# network rather than an inventory dump.
LIMIT = 200


class NetBox(connectors.Connector):
    NAME = "netbox"
    LABEL = "NetBox"
    HELP = "Network source of truth: devices, addresses, prefixes and VLANs per site"
    COMPANY_WORD = "tenant"

    def headers(self):
        token = self.token()
        if not token:
            raise ConnectorError(
                "NetBox needs an API token. Make one under your profile, put it "
                "in a file, and run: toolbox assist connector add netbox "
                "--url https://netbox.example.com --token-file ~/.netbox-token")
        scheme = self.config.get("scheme") or "Token"
        return {"Authorization": "%s %s" % (scheme, token),
                "Accept": "application/json"}

    def _api(self):
        return connectors.Session(self.url.rstrip("/") + "/api",
                                  headers=self.headers())

    def check(self):
        session = self._api()
        payload = session.get("/status/")
        version = payload.get("netbox-version") or payload.get("netbox_version")
        if version:
            return True, "reached %s, NetBox %s" % (self.host(), version)
        return True, "reached %s" % self.host()

    def companies(self, query=""):
        """NetBox calls them tenants."""
        session = self._api()
        rows = session.follow("/tenancy/tenants/",
                              {"q": query or None, "limit": LIMIT})
        return [{"id": row.get("id"), "name": row.get("name", "")} for row in rows]

    def fetch(self, link):
        tenant = link.get("company_id")
        if not tenant:
            raise ConnectorError("this client is not linked to a NetBox tenant yet")
        session = self._api()
        facts, documents = [], []
        scope = {"tenant_id": tenant, "limit": LIMIT}

        devices = session.follow("/dcim/devices/", scope)
        lines = []
        for device in devices:
            name = device.get("name") or "(unnamed)"
            role = _label(device.get("role") or device.get("device_role"))
            model = _label(device.get("device_type"))
            site = _label(device.get("site"))
            address = _address(device.get("primary_ip4") or device.get("primary_ip"))
            if address:
                facts.append({"label": name, "value": address})
            lines.append("%s  %s  %s  %s  %s"
                         % (name, role or "-", model or "-", site or "-",
                            address or "-"))
        if lines:
            documents.append({
                "name": "netbox-devices.txt",
                "text": "DEVICES IN NETBOX\nname / role / model / site / address\n"
                        + "\n".join(lines),
                "url": "%s/dcim/devices/?tenant_id=%s" % (self.url, tenant),
            })

        prefixes = session.follow("/ipam/prefixes/", scope)
        for prefix in prefixes:
            site = _label(prefix.get("site")) or _label(prefix.get("scope"))
            description = prefix.get("description") or ""
            label = site or description or "prefix"
            facts.append({"label": "%s subnet" % label, "value": prefix.get("prefix", "")})

        vlans = session.follow("/ipam/vlans/", scope)
        for vlan in vlans:
            if vlan.get("vid") is None:
                continue
            facts.append({"label": "VLAN %s" % vlan["vid"],
                          "value": vlan.get("name") or ""})

        sites = session.follow("/dcim/sites/", {"tenant_id": tenant, "limit": LIMIT})
        for site in sites:
            facts.append({"label": "site", "value": site.get("name", "")})

        # Drop anything that came back without a value rather than putting an
        # empty fact into someone's standing context.
        facts = [fact for fact in facts if fact["label"] and fact["value"]]
        return {"documents": documents, "facts": facts}


def _label(value):
    if isinstance(value, dict):
        return value.get("display") or value.get("name") or ""
    return value or ""


def _address(value):
    """A primary IP, without the prefix length - it is a host address here."""
    if not isinstance(value, dict):
        return ""
    address = value.get("address") or ""
    return address.split("/")[0]
