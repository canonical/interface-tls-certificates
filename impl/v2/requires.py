import uuid

from ..common import CertificateRequest, Certificate
from ..versions import VersionedProtocol
from charmhelpers.core import unitdata

LOCAL_UNIT_ID = unitdata.kv().get('tls-certificates.unit.id')
if not LOCAL_UNIT_ID:
    LOCAL_UNIT_ID = str(uuid.uuid4())
    unitdata.kv().set('tls-certificates.unit.id', LOCAL_UNIT_ID)


class Requires(VersionedProtocol):
    VERSION = 2

    def upgrade_from(self, old_version):
        for request in old_version.requests:
            self._request_cert(request)

    def clear(self):
        for key in self._pub_json.keys():
            if key.startswith(self._version_prefix):
                self._pub_json[key] = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._version_prefix = 'v{}.'.format(self.VERSION)
        self._requests = self._read_requests()
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

    def _read_requests(self):
        requests = []
        for key, value in self._pub_json.items():
            if not key.startswith(self._version_prefix):
                continue
            requests.append(CertificateRequest(unit=None, **value))
        return requests

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

    def request_cert(self, cert_type, common_name, sans, cert_name=None):
        self._request_cert(CertificateRequest(unit=None,
                                              cert_type=cert_type,
                                              common_name=common_name,
                                              sans=sans,
                                              cert_name=cert_name))

    def _request_cert(self, cert_req):
        self._pub_json[self._version_prefix + 'requestor'] = LOCAL_UNIT_ID
        key = '{version}{cert_type}.{common_name}'.format(
            version=self._version_prefix,
            **cert_req)
        self._pub_json[key] = cert_req
