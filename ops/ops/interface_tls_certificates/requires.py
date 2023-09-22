# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""Implementation of tls-certificates interface.

This only implements the requires side, currently, since the providers
is still using the Reactive Charm framework self.
"""
import json
import logging
import uuid
from backports.cached_property import cached_property
from typing import List, Mapping, Optional

from ops.charm import CharmBase, RelationBrokenEvent
from ops.framework import Object
from pydantic import ValidationError

from .model import Data, Certificate

log = logging.getLogger(__name__)


class CertificatesRequires(Object):
    """Requires side of certificates relation."""

    def __init__(self, charm: CharmBase, endpoint="certificates"):
        super().__init__(charm, f"relation-{endpoint}")
        self.endpoint = endpoint
        self._unit_name = self.model.unit.name.replace("/", "_")

        events = charm.on[endpoint]
        self.framework.observe(events.relation_joined, self._joined)

    def _joined(self, event=None):
        event.relation.data[self.model.unit]["unit_name"] = self._unit_name

    @cached_property
    def relation(self):
        """The relation to the integrator, or None."""
        return self.model.get_relation(self.endpoint)

    @cached_property
    def _raw_data(self):
        if self.relation and self.relation.units:
            return self.relation.data[list(self.relation.units)[0]]
        return None

    @cached_property
    def _data(self) -> Optional[Data]:
        raw = self._raw_data
        return Data(**raw) if raw else None

    def evaluate_relation(self, event) -> Optional[str]:
        """Determine if relation is ready."""
        no_relation = not self.relation or (
            isinstance(event, RelationBrokenEvent) and event.relation is self.relation
        )
        if not self.is_ready:
            if no_relation:
                return f"Missing required {self.endpoint}"
            return f"Waiting for {self.endpoint}"
        return None

    @property
    def is_ready(self):
        """Whether the request for this instance has been completed."""
        try:
            self._data
        except ValidationError as ve:
            log.error(f"{self.endpoint} relation data not yet valid. ({ve}")
            return False
        if self._data is None:
            log.error(f"{self.endpoint} relation data not yet available.")
            return False
        return True

    @property
    def ca(self):
        """The ca value."""
        if not self.is_ready:
            return None

        return self._data.ca

    @property
    def client_certs(self) -> List[Certificate]:
        """Certificate instances for all available client certs."""
        if not self.is_ready:
            return []

        field = f"{self._unit_name}.processed_client_requests"
        certs_json = getattr(self._data, field, "{}")
        certs_data = json.loads(certs_json)
        return [
            Certificate(cert_type="client", common_name=common_name, **cert)
            for common_name, cert in certs_data.items()
        ]

    @property
    def client_certs_map(self) -> Mapping[str, Certificate]:
        """Certificate instances by their `common_name`."""
        return {cert.common_name: cert for cert in self.client_certs}

    def request_client_cert(self, cn, sans=None):
        """Request Client certificate for charm.

        Request a client certificate and key be generated for the given
        common name (`cn`) and list of alternative names (`sans`).
        This can be called multiple times to request more than one client
        certificate, although the common names must be unique.  If called
        again with the same common name, it will be ignored.
        """
        if not self.relation:
            return
        # assume we'll only be connected to one provider
        data = self.relation.data[self.model.unit]
        requests = json.loads(data.get("client_cert_requests", "{}"))
        requests[cn] = {"sans": sans}
        data["client_cert_requests"] = json.dumps(requests)

    def request_server_cert(self, cn, sans=None, cert_name=None):
        """
        Request a server certificate and key be generated for the given
        common name (`cn`) and optional list of alternative names (`sans`).
        The `cert_name` is deprecated and not needed.
        This can be called multiple times to request more than one server
        certificate, although the common names must be unique.  If called
        again with the same common name, it will be ignored.
        """
        if not self.relation:
            return
        # assume we'll only be connected to one provider
        data = self.relation.data[self.model.unit]
        if data.get("common_name") in (None, "", cn):
            # for backwards compatibility, first request goes in its own fields
            data["common_name"] = cn
            data["sans"] = json.dumps(sans or [])
            cert_name = data.get("certificate_name") or cert_name
            if cert_name is None:
                cert_name = str(uuid.uuid4())
            data["certificate_name"] = cert_name
        else:
            # subsequent requests go in the collection
            requests = data.get("cert_requests", {})
            requests[cn] = {"sans": sans or []}
            data["cert_requests"] = json.dumps(requests)

    @property
    def server_certs(self) -> List[Certificate]:
        """
        List of [Certificate][] instances for all available server certs.
        """
        if not self.relation:
            log.warning(f"Relation {self.endpoint} is not yet available.")
            return []
        common_name = self.relation.data[self.model.unit].get("common_name")
        if common_name is None or not self.is_ready:
            log.warning(f"Relation {self.endpoint} is not yet available.")
            return []

        certs = []
        cert = getattr(self._data, f"{self._unit_name}.server.cert", None)
        key = getattr(self._data, f"{self._unit_name}.server.key", None)
        if cert and key:
            certs.append(
                Certificate(
                    cert_type="server", common_name=common_name, cert=cert, key=key
                )
            )

        field = f"{self._unit_name}.processed_requests"
        certs_json = getattr(self._data, field, "{}")
        certs_data = json.loads(certs_json)
        return certs + [
            Certificate(cert_type="server", common_name=common_name, **cert)
            for common_name, cert in certs_data.items()
        ]

    @property
    def server_certs_map(self) -> Mapping[str, Certificate]:
        """Certificate instances by their `common_name`."""
        return {cert.common_name: cert for cert in self.server_certs}
