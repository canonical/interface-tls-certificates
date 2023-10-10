if not __package__:
    # fix relative imports when building docs
    import sys

    __package__ = sys.modules[""].__name__

import uuid

from charmhelpers.core import hookenv

from charms.reactive import when, when_not
from charms.reactive import set_flag, clear_flag, toggle_flag
from charms.reactive import Endpoint
from charms.reactive import data_changed

from .tls_certificates_common import Certificate


class TlsRequires(Endpoint):
    """
    The client's side of the interface protocol.

    The following flags may be set:

      * `{endpoint_name}.available`
        Whenever the relation is joined.

      * `{endpoint_name}.ca.available`
        When the root CA information is available via the [root_ca_cert][] and
        [root_ca_chain][] properties.

      * `{endpoint_name}.ca.changed`
        When the root CA information has changed, whether because
        they have just become available or if they were regenerated by the CA.
        Once processed this flag should be removed by the charm.

      * `{endpoint_name}.certs.available`
        When the requested server or client certs are available.

      * `{endpoint_name}.certs.changed`
        When the requested server or client certs have changed, whether because
        they have just become available or if they were regenerated by the CA.
        Once processed this flag should be removed by the charm.

      * `{endpoint_name}.server.certs.available`
        When the server certificates requested by [request_server_cert][] are
        available via the [server_certs][] collection.

      * `{endpoint_name}.server.certs.changed`
        When the requested server certificates have changed, whether because
        they have just become available or if they were regenerated by the CA.
        Once processed this flag should be removed by the charm.

      * `{endpoint_name}.client.certs.available`
        When the client certificates requested by [request_client_cert][] are
        available via the [client_certs][] collection.

      * `{endpoint_name}.client.certs.changed`
        When the requested client certificates have changed, whether because
        they have just become available or if they were regenerated by the CA.
        Once processed this flag should be removed by the charm.

    The following flags have been deprecated:

      * `{endpoint_name}.server.cert.available`
      * `{endpoint_name}.client.cert.available`
      * `{endpoint_name}.batch.cert.available`

    [Certificate]: common.md#tls_certificates_common.Certificate
    [CertificateRequest]: common.md#tls_certificates_common.CertificateRequest
    [root_ca_cert]: requires.md#requires.TlsRequires.root_ca_cert
    [root_ca_chain]: requires.md#requires.TlsRequires.root_ca_chain
    [request_server_cert]: requires.md#requires.TlsRequires.request_server_cert
    [request_client_cert]: requires.md#requires.TlsRequires.request_client_cert
    [server_certs]: requires.md#requires.TlsRequires.server_certs
    [server_certs_map]: requires.md#requires.TlsRequires.server_certs_map
    [client_certs]: requires.md#requires.TlsRequires.server_certs
    """

    @when("endpoint.{endpoint_name}.joined")
    def joined(self):
        self.relations[0].to_publish_raw["unit_name"] = self._unit_name
        prefix = self.expand_name("{endpoint_name}.")
        ca_available = self.root_ca_cert
        ca_changed = ca_available and data_changed(prefix + "ca", self.root_ca_cert)
        server_available = self.server_certs
        server_changed = server_available and data_changed(
            prefix + "servers", self.server_certs
        )
        client_available = self.client_certs
        client_changed = client_available and data_changed(
            prefix + "clients", self.client_certs
        )
        intermediate_available = self.intermediate_certs
        intermediate_changed = intermediate_available and data_changed(
            prefix + "intermediates", self.intermediate_certs
        )
        certs_available = server_available or client_available or intermediate_available
        certs_changed = server_changed or client_changed or intermediate_changed

        set_flag(prefix + "available")
        toggle_flag(prefix + "ca.available", ca_available)
        toggle_flag(prefix + "ca.changed", ca_changed)
        toggle_flag(prefix + "server.certs.available", server_available)
        toggle_flag(prefix + "server.certs.changed", server_changed)
        toggle_flag(prefix + "client.certs.available", client_available)
        toggle_flag(prefix + "client.certs.changed", client_changed)
        toggle_flag(prefix + "intermediate.certs.available", intermediate_available)
        toggle_flag(prefix + "intermediate.certs.changed", intermediate_changed)
        toggle_flag(prefix + "certs.available", certs_available)
        toggle_flag(prefix + "certs.changed", certs_changed)
        # deprecated
        toggle_flag(prefix + "server.cert.available", self.server_certs)
        toggle_flag(prefix + "client.cert.available", self.get_client_cert())
        toggle_flag(prefix + "batch.cert.available", self.server_certs)

    @when_not("endpoint.{endpoint_name}.joined")
    def broken(self):
        prefix = self.expand_name("{endpoint_name}.")
        clear_flag(prefix + "available")
        clear_flag(prefix + "ca.available")
        clear_flag(prefix + "ca.changed")
        clear_flag(prefix + "server.certs.available")
        clear_flag(prefix + "server.certs.changed")
        clear_flag(prefix + "client.certs.available")
        clear_flag(prefix + "client.certs.changed")
        clear_flag(prefix + "intermediate.certs.available")
        clear_flag(prefix + "intermediate.certs.changed")
        clear_flag(prefix + "certs.available")
        clear_flag(prefix + "certs.changed")
        # deprecated
        clear_flag(prefix + "server.cert.available")
        clear_flag(prefix + "client.cert.available")
        clear_flag(prefix + "batch.cert.available")

    @property
    def _unit_name(self):
        return hookenv.local_unit().replace("/", "_")

    @property
    def root_ca_cert(self):
        """
        Root CA certificate.
        """
        # only the leader of the provider should set the CA, or all units
        # had better agree
        return self.all_joined_units.received_raw["ca"]

    def get_ca(self):
        """
        Return the root CA certificate.

        Same as [root_ca_cert][].
        """
        return self.root_ca_cert

    @property
    def root_ca_chain(self):
        """
        The chain of trust for the root CA.
        """
        # only the leader of the provider should set the CA, or all units
        # had better agree
        return self.all_joined_units.received_raw["chain"]

    def get_chain(self):
        """
        Return the chain of trust for the root CA.

        Same as [root_ca_chain][].
        """
        return self.root_ca_chain

    def get_client_cert(self):
        """
        Deprecated.  Use [request_client_cert][] and the [client_certs][]
        collection instead.

        Return a globally shared client certificate and key.
        """
        data = self.all_joined_units.received_raw
        return (data["client.cert"], data["client.key"])

    def get_server_cert(self):
        """
        Deprecated.  Use the [server_certs][] collection instead.

        Return the cert and key of the first server certificate requested.
        """
        if not self.server_certs:
            return (None, None)
        cert = self.server_certs[0]
        return (cert.cert, cert.key)

    @property
    def server_certs(self):
        """
        List of [Certificate][] instances for all available server certs.
        """
        certs = []
        raw_data = self.all_joined_units.received_raw
        json_data = self.all_joined_units.received

        # for backwards compatibility, the first cert goes in its own fields
        if self.relations:
            common_name = self.relations[0].to_publish_raw["common_name"]
            cert = raw_data["{}.server.cert".format(self._unit_name)]
            key = raw_data["{}.server.key".format(self._unit_name)]
            if cert and key:
                certs.append(Certificate("server", common_name, cert, key))

        # subsequent requests go in the collection
        field = "{}.processed_requests".format(self._unit_name)
        certs_data = json_data[field] or {}
        certs.extend(
            Certificate("server", common_name, cert["cert"], cert["key"])
            for common_name, cert in certs_data.items()
        )
        return certs

    @property
    def application_certs(self):
        """
        List containg the application Certificate cert.

        :returns: A list containing one certificate
        :rtype: [Certificate()]
        """
        certs = []
        json_data = self.all_joined_units.received
        field = "{}.processed_application_requests".format(self._unit_name)
        certs_data = json_data[field] or {}
        app_cert_data = certs_data.get("app_data")
        if app_cert_data:
            certs = [
                Certificate(
                    "server", "app_data", app_cert_data["cert"], app_cert_data["key"]
                )
            ]
        return certs

    @property
    def server_certs_map(self):
        """
        Mapping of server [Certificate][] instances by their `common_name`.
        """
        return {cert.common_name: cert for cert in self.server_certs}

    def get_batch_requests(self):
        """
        Deprecated.  Use [server_certs_map][] instead.

        Mapping of server [Certificate][] instances by their `common_name`.
        """
        return self.server_certs_map

    @property
    def client_certs(self):
        """
        List of [Certificate][] instances for all available client certs.
        """
        field = "{}.processed_client_requests".format(self._unit_name)
        certs_data = self.all_joined_units.received[field] or {}
        return [
            Certificate("client", common_name, cert["cert"], cert["key"])
            for common_name, cert in certs_data.items()
        ]

    @property
    def client_certs_map(self):
        """
        Mapping of client [Certificate][] instances by their `common_name`.
        """
        return {cert.common_name: cert for cert in self.client_certs}

    @property
    def intermediate_certs(self):
        """
        List of [Certificate][] instances for all available intermediate CA certs.
        """
        certs = []
        json_data = self.all_joined_units.received
        field = "{}.processed_intermediate_requests".format(self._unit_name)
        certs_data = json_data[field] or {}
        app_cert_data = certs_data.get("app_data")
        if app_cert_data:
            certs = [
                Certificate(
                    "intermediate",
                    "app_data",
                    app_cert_data["cert"],
                    app_cert_data["key"],
                )
            ]
        return certs

    @property
    def intermediate_certs_map(self):
        """
        Mapping of intermediate CA [Certificate][] instances by their `common_name`.
        """
        return {cert.common_name: cert for cert in self.intermediate_certs}

    def request_server_cert(self, cn, sans=None, cert_name=None):
        """
        Request a server certificate and key be generated for the given
        common name (`cn`) and optional list of alternative names (`sans`).

        The `cert_name` is deprecated and not needed.

        This can be called multiple times to request more than one server
        certificate, although the common names must be unique.  If called
        again with the same common name, it will be ignored.
        """
        if not self.relations:
            return
        # assume we'll only be connected to one provider
        to_publish_json = self.relations[0].to_publish
        to_publish_raw = self.relations[0].to_publish_raw
        if to_publish_raw["common_name"] in (None, "", cn):
            # for backwards compatibility, first request goes in its own fields
            to_publish_raw["common_name"] = cn
            to_publish_json["sans"] = sans or []
            cert_name = to_publish_raw.get("certificate_name") or cert_name
            if cert_name is None:
                cert_name = str(uuid.uuid4())
            to_publish_raw["certificate_name"] = cert_name
        else:
            # subsequent requests go in the collection
            requests = to_publish_json.get("cert_requests", {})
            requests[cn] = {"sans": sans or []}
            to_publish_json["cert_requests"] = requests

    def add_request_server_cert(self, cn, sans):
        """
        Deprecated.  Use [request_server_cert][] instead.
        """
        self.request_server_cert(cn, sans)

    def request_server_certs(self):
        """
        Deprecated.  Just use [request_server_cert][]; this does nothing.
        """
        pass

    def request_client_cert(self, cn, sans):
        """
        Request a client certificate and key be generated for the given
        common name (`cn`) and list of alternative names (`sans`).

        This can be called multiple times to request more than one client
        certificate, although the common names must be unique.  If called
        again with the same common name, it will be ignored.
        """
        if not self.relations:
            return
        # assume we'll only be connected to one provider
        to_publish_json = self.relations[0].to_publish
        requests = to_publish_json.get("client_cert_requests", {})
        requests[cn] = {"sans": sans}
        to_publish_json["client_cert_requests"] = requests

    def request_application_cert(self, cn, sans):
        """
        Request an application certificate and key be generated for the given
        common name (`cn`) and list of alternative names (`sans` ) of this
        unit and all peer units. All units will share a single certificates.
        """
        if not self.relations:
            return
        # assume we'll only be connected to one provider
        to_publish_json = self.relations[0].to_publish
        requests = to_publish_json.get("application_cert_requests", {})
        requests[cn] = {"sans": sans}
        to_publish_json["application_cert_requests"] = requests

    def request_intermediate_cert(self, cn, sans):
        """
        Request an intermediate CA certificate and key be generated for the given
        common name (`cn`) and list of alternative names (`sans`).

        This can be called multiple times to request more than one client
        certificate, although the common names must be unique.  If called
        again with the same common name, it will be ignored.
        """
        if not self.relations:
            return
        # assume we'll only be connected to one provider
        to_publish_json = self.relations[0].to_publish
        requests = to_publish_json.get("intermediate_cert_requests", {})
        requests[cn] = {"sans": sans}
        to_publish_json["intermediate_cert_requests"] = requests
