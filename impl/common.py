from charms.reactive import is_data_changed, data_changed, clear_flag


class CertificateRequest(dict):
    def __init__(self, unit, cert_type, common_name, sans, cert_name,
                 cert=None):
        self._unit = unit
        self._cert = cert
        super().__init__({
            'cert_type': cert_type,
            'common_name': common_name,
            'sans': sans,
            'cert_name': cert_name,
        })

    def __missing__(self, key):
        if key == 'certificate_name':
            return self.cert_name
        else:
            raise KeyError(key)

    @property
    def unit(self):
        """
        The remote Unit instance which issued this request.
        """
        return self._unit

    @property
    def relation(self):
        """
        The Relation instance for the Unit which issued this request.
        """
        return self.unit.relation

    @property
    def cert_type(self):
        """
        Type of certificate, 'server' or 'client', being requested.
        """
        return self['cert_type']

    @property
    def cert_name(self):
        """
        Deprecated.  An optional name used to identify the certificate.
        """
        return self['cert_name']

    @property
    def common_name(self):
        """
        Common Name (CN) field requested for the cert.
        """
        return self['common_name']

    @property
    def sans(self):
        """
        List of Subject Alternative Names (SANs) requested for the cert.
        """
        return self['sans']

    @property
    def cert(self):
        """
        The cert published for this request, if any.

        This will either be a Certificate instance or None.
        """
        return self._cert

    @property
    def _data_key(self):
        """
        Key used to track whether request data has changed.
        """
        return '.'.join((self.relation.relation_id,
                         self.unit.unit_name,
                         self.common_name))

    @property
    def is_handled(self):
        """
        Whether or not this request has been handled (a cert has been generated
        for the most recently requested CN and SANs).
        """
        has_cert = self.cert is not None
        same_sans = not is_data_changed(self._data_key, self.sans)
        return has_cert and same_sans

    def set_cert(self, cert, key):
        """
        Create or update the Certificate for this request, and publish it.

        This will also adjust *.requested flags for the endpoint, as
        appropriate.
        """
        self._cert = Certificate(cert_type=self.cert_type,
                                 common_name=self.common_name,
                                 cert=cert,
                                 key=key)
        self.relation.protocol.set_cert(self)
        data_changed(self._data_key, self.sans)
        # update the endpoint's flags to reflect our change in state
        if not self.relation.endpoint.new_server_requests:
            clear_flag(self.relation.endpoint.expand_name(
                '{endpoint_name}.server.certs.requested'))
            # deprecated legacy flag
            clear_flag(self.relation.endpoint.expand_name(
                '{endpoint_name}.server.cert.requested'))
        if not self.relation.endpoint.new_client_requests:
            clear_flag(self.relation.endpoint.expand_name(
                '{endpoint_name}.client.certs.requested'))
            # deprecated legacy flag
            clear_flag(self.relation.endpoint.expand_name(
                '{endpoint_name}.client.cert.requested'))
        if not self.relation.endpoint.new_requests:
            clear_flag(self.relation.endpoint.expand_name(
                '{endpoint_name}.certs.requested'))


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
        """
        The type of cert, 'server' or 'client'.
        """
        return self['cert_type']

    @property
    def common_name(self):
        """
        The Common Name (CN) for this certificate.
        """
        return self['common_name']

    @property
    def cert(self):
        """
        The public certificate data.
        """
        return self['cert']

    @property
    def key(self):
        """
        The private key for this certificate.
        """
        return self['key']
