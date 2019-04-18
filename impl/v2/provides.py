from ..common import (
    CertificateRequest,
    Certificate,
)
from ..versions import VersionedProtocol


class Provides(VersionedProtocol):
    VERSION = 1

    def upgrade_from(self, old_version):
        raise NotImplementedError()

    def clear(self):
        rel = self.relation
        rel.to_publish_raw.update({
            'ca': None,
            'chain': None,
            'client.cert': None,
            'client.key': None,
        })
        for key in rel.to_publish_raw.keys():
            if key.endswith('.server.cert') or key.endswith('.server.key'):
                del rel.to_publish_raw[key]
        for key in rel.to_publish.keys():
            if key.endswith('.processed_requests') or \
               key.endswith('.processed_client_requests'):
                del rel.to_publish[key]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._requests = self._read_requests()

    def _read_requests(self):
        requests = []
        for unit in self.relation.joined_units:
            rel = self.relation
            unit_name = unit.unit_name.replace('/', '_')
            # handle older single server cert request
            common_name = unit.received_raw.get('common_name')
            if common_name:
                # first check if request already has a response
                cert = rel.to_publish_raw['{}.server.cert'.format(unit_name)]
                key = rel.to_publish_raw['{}.server.key'.format(unit_name)]
                # create the request
                requests.append(CertificateRequest(
                    unit=unit,
                    cert_type='server',
                    common_name=common_name,
                    sans=unit.received['sans'],
                    cert_name=unit.received_raw['certificate_name'],
                    cert=Certificate(cert_type='server',
                                     common_name=common_name,
                                     cert=cert,
                                     key=key,
                                     ) if cert and key else None,
                ))
                # patch in to req for easier filtering later
                requests[-1]._is_top_level_server_cert_request = True

            cert_types = {
                'server': ('cert_requests',
                           '{}.processed_requests'.format(unit_name)),
                'client': ('client_cert_requests',
                           '{}.processed_client_requests'.format(unit_name)),
            }
            for cert_type, (req_key, resp_key) in cert_types.items():
                reqs = unit.received[req_key] or {}
                certs = rel.to_publish.get(resp_key, {})
                for common_name, req in reqs.items():
                    requests.append(CertificateRequest(
                        unit=unit,
                        cert_type=cert_type,
                        common_name=common_name,
                        sans=req['sans'],
                        cert_name=common_name,
                        cert=Certificate(cert_type=cert_type,
                                         common_name=common_name,
                                         cert=certs[common_name]['cert'],
                                         key=certs[common_name]['key'],
                                         ) if common_name in certs else None,
                    ))
                    # patch in to req for easier filtering later
                    requests[-1]._is_top_level_server_cert_request = False
        return requests

    @property
    def requests(self):
        return self._requests

    @property
    def responses(self):
        return self._responses

    def set_root_ca_cert(self, cert):
        for relation in self.endpoint.relations:
            # All the clients get the same CA, so send it to them.
            relation.to_publish_raw['ca'] = cert

    def set_root_ca_chain(self, chain):
        for relation in self.endpoint.relations:
            # All the clients get the same chain, so send it to them.
            relation.to_publish_raw['chain'] = chain

    def set_global_client_cert(self, cert, key):
        for relation in self.endpoint.relations:
            relation.to_publish_raw.update({
                'client.cert': cert,
                'client.key': key,
            })

    def set_cert(self, request):
        rel = self.relation
        unit_name = request.unit.unit_name.replace('/', '_')
        if request._is_top_level_server_cert_request:
            # backwards compatibility; if this is the cert that was requested
            # as a single server cert, set it in the response as the single
            # server cert
            rel.to_publish_raw.update({
                '{}.server.cert'.format(unit_name): request.cert.cert,
                '{}.server.key'.format(unit_name): request.cert.key,
            })
        else:
            if request.cert_type == 'server':
                publish_key = '{}.processed_requests'
            elif request.cert_type == 'client':
                publish_key = '{}.processed_client_requests'
            else:
                raise ValueError('Unknown cert_type: '
                                 '{}'.format(request.cert_type))
            publish_key = publish_key.format(unit_name)
            data = rel.to_publish.get(publish_key, {})
            data[request.common_name] = {
                'cert': request.cert.cert,
                'key': request.cert.key,
            }
            # have to explicit store to ensure serialized data is updated
            rel.to_publish[publish_key] = data
