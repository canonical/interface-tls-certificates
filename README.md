# tls-certificates

This is a [Juju](https://jujucharms.com) interface layer that handles the
transport layer security (TLS) for charms. Using relations between charms.  
Meaning the charms that use this layer can communicate securely
with each other based on TLS certificates.

To get started please read the
[Introduction to PKI](https://github.com/OpenVPN/easy-rsa/blob/master/doc/Intro-To-PKI.md)
which defines some PKI terms, concepts and processes used in this document.

> **NOTE**: It is important to point out that this interface does not do the 
actual work of issuing certificates. The interface layer only handles the 
communication between the peers and the charm layer must react to the states 
correctly for this interface to work.  

The [layer-tls](https://github.com/mbruzek/layer-tls) charm layer was created
to implement this using the [easy-rsa](https://github.com/OpenVPN/easy-rsa)
project.  This interface could be implemented with other PKI technology tools
(such as openssl commands) in other charm layers.

# States

The interface layer emits several reactive states that a charm layer can respond
to:

## {relation_name}.available
This is the start state that is generated when the relation is joined.
A charm layer responding to this state should get the common name, a list of 
Subject Alt Names, and the certificate_name call 
`request_server_cert(common_name, sans, certificate_name)` on the relation 
object.

## {relation_name}.ca.available
The Certificate Authority is available on the relation object when the 
"{relation_name}.ca.available" state is set. The charm layer can retrieve the
CA by calling `get_ca()` method on the relationship object.

```python
from charms.reactive import when
@when('certificates.ca.available')
def store_ca(tls):
    certificate_authority = tls.get_ca()
```

## {relation_name}.server.cert.available
Once the server certificate is set on the relation the interface layer will
emit the "{relation_name}.server.cert.available" state, indicating that the 
server certificate is available from the relationship object.  The charm layer 
can retrieve the certificate and use it in the code by calling the
`get_server_cert()` method on the relationship object.

```python
from charms.reactive import when
@when('certificates.server.cert.available')
def get_server(tls):
    server_cert, server_key = tls.get_server_cert()
```

## {relation_name}.client.cert.available
Once the client certificate is set on the relation the interface layer will
emit the "{relation_name}.client.cert.available" state, indicated that the
server certificates is available from the relationship object.  The charm layer
can retrieve the certificate and use it in the code by calling the
`get_client_cert()` method on the relationship object.

```python
from charms.reactive import when
@when('certificates.client.cert.available')
def store_client(tls):
    client_cert, client_key = tls.get_client_cert()
```

# Contact Information

Interface author: Matt Bruzek &lt;Matthew.Bruzek@canonical.com&gt; 

Contributor: Charles Butler &lt;Charles.Butler@canonical.com&gt; 

Contributor: Cory Johns &lt;Cory.Johns@canonical.com&gt; 
