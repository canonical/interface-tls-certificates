import uuid

from ..common import Certificate
from ..versions import VersionedProtocol
from charmhelpers.core import hookenv

LOCAL_UNIT_NAME = hookenv.local_unit().replace('/', '_')


class Requires(VersionedProtocol):
    VERSION = 1

    class fields:
        root_ca_cert = 'ca'
        root_ca_chain = 'chain'
        legacy_server_cert = LOCAL_UNIT_NAME + '.server.cert'
        legacy_server_key = LOCAL_UNIT_NAME + '.server.key'
        legacy_client_cert = 'client.cert'
        legacy_client_key = 'client.key'
        server_certs = LOCAL_UNIT_NAME + '.processed_requests'
        client_certs = LOCAL_UNIT_NAME + '.processed_client_requests'
        legacy_server_common_name = 'common_name'
        legacy_server_sans = 'sans'
        legacy_server_cert_name = 'certificate_name'
        server_requests = 'cert_requests'
        client_requests = 'client_cert_requests'

    def upgrade_from(self, old_version):
        raise NotImplementedError()

    def clear(self):
        self.relation._pub_raw.update({
            self.fields.legacy_server_common_name: None,
            self.fields.legacy_server_sans: None,
            self.fields.legacy_server_cert_name: None,
        })
        self.relation._pub_json.update({
            self.fields.server_requests: None,
            self.fields.client_requests: None,
        })

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ca_info = self._read_ca_info()
        self._certs = self._read_certs()
        self._global_client_cert = self._read_global_client_cert()

    @property
    def _rcv_raw(self):
        # assume we'll only be connected to one provider
        return self.relation.joined_units.received_raw

    @property
    def _rcv_json(self):
        # assume we'll only be connected to one provider
        return self.relation.joined_units.received

    @property
    def _pub_raw(self):
        return self.relation.to_publish_raw

    @property
    def _pub_json(self):
        return self.relation.to_publish

    def _read_ca_info(self):
        # only the leader of the provider should set the CA, or all units
        # had better agree
        return {
            'cert': self._rcv_raw[self.fields.root_ca_cert],
            'chain': self._rcv_raw[self.fields.root_ca_chain],
        }

    def _read_certs(self):
        certs = {'server': {}, 'client': {}}

        # for backwards compatibility, the first server cert has its own fields
        cert = self._rcv_raw[self.fields.legacy_server_cert]
        key = self._rcv_raw[self.fields.legacy_server_key]
        if cert and key:
            common_name = self._pub_raw[self.fields.legacy_server_common_name]
            certs['server'][common_name] = Certificate('server',
                                                       common_name,
                                                       cert,
                                                       key)

        # subsequent server certs go in the collection
        # client certs are newer, so all go in the collection
        for cert_type, field in (('server', self.fields.server_certs),
                                 ('client', self.fields.client_certs)):
            certs_data = self._rcv_json[field] or {}
            for common_name, cert in certs_data.items():
                certs[cert_type][common_name] = Certificate(cert_type,
                                                            common_name,
                                                            cert['cert'],
                                                            cert['key'])
        return certs

    def _read_global_client_cert(self):
        return Certificate(
            'client',
            'client',
            self._rcv_raw[self.fields.legacy_client_cert],
            self._rcv_raw[self.fields.legacy_client_key],
        )

    @property
    def root_ca_cert(self):
        """
        Certificate for the root CA.
        """
        return self._ca_info['cert']

    @property
    def root_ca_chain(self):
        """
        Trust chain information for the root CA.
        """
        return self._ca_info['chain']

    @property
    def global_client_cert(self):
        """
        Deprecated global client Certificate.
        """
        return self._global_client_cert

    @property
    def server_certs(self):
        """
        Mapping of common names to server Certificates.
        """
        return self._certs['server']

    @property
    def client_certs(self):
        """
        Mapping of common names to client Certificates.
        """
        return self._certs['client']

    def request_server_cert(self, common_name, sans, cert_name=None):
        # for backwards compatibility, populate cert name
        if not cert_name:
            cert_name = str(uuid.uuid4())
        published_cn = self._pub_raw[self.fields.legacy_server_common_name]
        if published_cn in (None, '', common_name):
            # for backwards compatibility, first request goes in its own fields
            self._pub_raw[self.fields.legacy_server_common_name] = common_name
            self._pub_json[self.fields.legacy_server_sans] = sans or []
            self._pub_raw[self.fields.legacy_server_cert_name] = cert_name
        else:
            # subsequent requests go in the collection
            requests = self._pub_json.get(self.fields.server_requests, {})
            requests[common_name] = {'sans': sans or []}
            self._pub_json[self.fields.server_requests] = requests

    def request_client_cert(self, common_name, sans):
        requests = self._pub_json.get('client_cert_requests', {})
        requests[common_name] = {'sans': sans}
        self._pub_json['client_cert_requests'] = requests
