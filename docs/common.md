<h1 id="tls_certificates_common.CertificateRequest">CertificateRequest</h1>

```python
CertificateRequest(self, unit, cert_type, cert_name, common_name, sans)
```

<h2 id="tls_certificates_common.CertificateRequest.cert">cert</h2>


The cert published for this request, if any.

<h2 id="tls_certificates_common.CertificateRequest.cert_type">cert_type</h2>


Type of certificate, 'server' or 'client', being requested.

<h1 id="tls_certificates_common.Certificate">Certificate</h1>

```python
Certificate(self, cert_type, common_name, cert, key)
```

Represents a created certificate and key.

The ``cert_type``, ``common_name``, ``cert``, and ``key`` values can
be accessed either as properties or as the contents of the dict.

