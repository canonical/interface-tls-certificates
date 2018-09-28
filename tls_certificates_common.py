from charms.reactive import clear_flag, is_data_changed, data_changed


class CertificateRequest(dict):
    def __init__(self, unit, cert_type, cert_name, common_name, sans):
        self._unit = unit
        self._cert_type = cert_type
        super().__init__({
            'certificate_name': cert_name,
            'common_name': common_name,
            'sans': sans,
        })

    @property
    def _key(self):
        return '.'.join((self._unit.relation.relation_id,
                         self.unit_name,
                         self.common_name))

    @property
    def unit_name(self):
        return self._unit.unit_name

    @property
    def cert_type(self):
        """
        Type of certificate, 'server' or 'client', being requested.
        """
        return self._cert_type

    @property
    def cert_name(self):
        return self['certificate_name']

    @property
    def common_name(self):
        return self['common_name']

    @property
    def sans(self):
        return self['sans']

    @property
    def _publish_key(self):
        unit_name = self._unit.unit_name.replace('/', '_')
        if self.cert_type == 'server':
            return '{}.processed_requests'.format(unit_name)
        elif self.cert_type == 'client':
            return '{}.processed_client_requests'.format(unit_name)
        raise ValueError('Unknown cert_type: {}'.format(self.cert_type))

    @property
    def _server_cert_key(self):
        unit_name = self._unit.unit_name.replace('/', '_')
        return '{}.server.cert'.format(unit_name)

    @property
    def _server_key_key(self):
        unit_name = self._unit.unit_name.replace('/', '_')
        return '{}.server.key'.format(unit_name)

    @property
    def _is_top_level_server_cert(self):
        return (self.cert_type == 'server' and
                self.common_name == self._unit.received_raw['common_name'])

    @property
    def cert(self):
        """
        The cert published for this request, if any.
        """
        cert, key = None, None
        if self._is_top_level_server_cert:
            tpr = self._unit.relation.to_publish_raw
            cert = tpr[self._server_cert_key]
            key = tpr[self._server_key_key]
        else:
            tp = self._unit.relation.to_publish
            certs_data = tp.get(self._publish_key, {})
            cert_data = certs_data.get(self.common_name, {})
            cert = cert_data.get('cert')
            key = cert_data.get('key')
        if cert and key:
            return Certificate(self.cert_type, self.common_name, cert, key)
        return None

    @property
    def is_handled(self):
        has_cert = self.cert is not None
        same_sans = not is_data_changed(self._key, self.sans)
        return has_cert and same_sans

    def set_cert(self, cert, key):
        rel = self._unit.relation
        if self._is_top_level_server_cert:
            # backwards compatibility; if this is the cert that was requested
            # as a single server cert, set it in the response as the single
            # server cert
            rel.to_publish_raw.update({
                self._server_cert_key: cert,
                self._server_key_key: key,
            })
        else:
            data = rel.to_publish.get(self._publish_key, {})
            data[self.common_name] = {
                'cert': cert,
                'key': key,
            }
            rel.to_publish[self._publish_key] = data
        if not rel.endpoint.new_server_requests:
            clear_flag(rel.endpoint.expand_name('{endpoint_name}.server'
                                                '.cert.requested'))
        if not rel.endpoint.new_requests:
            clear_flag(rel.endpoint.expand_name('{endpoint_name}.'
                                                'certs.requested'))
        data_changed(self._key, self.sans)


class Certificate(dict):
    """
    Represents a created certificate and key.

    The ``cert_type``, ``common_name``, ``cert``, and ``key`` values can
    be accessed either as properties or as the contents of the dict.
    """
    def __init__(self, cert_type, common_name, cert, key):
        super().__init__({
            'cert_type': cert_type,
            'common_name': common_name,
            'cert': cert,
            'key': key,
        })

    @property
    def cert_type(self):
        return self['cert_type']

    @property
    def common_name(self):
        return self['common_name']

    @property
    def cert(self):
        return self['cert']

    @property
    def key(self):
        return self['key']
