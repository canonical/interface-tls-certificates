import json

from charms.reactive import hook
from charms.reactive import scopes
from charms.reactive import RelationBase


class TlsRequires(RelationBase):
    '''The class that requires a TLS relationship to another unit.'''
    # Use the gloabal scope for requires relation.
    scope = scopes.GLOBAL

    @hook('{requires:tls-certificates}-relation-joined')
    def joined(self):
        '''When joining with a TLS provider request a certificate..'''
        # Get the conversation scoped to the unit.
        conversation = self.conversation()
        conversation.set_state('{relation_name}.available')

    @hook('{requires:tls-certificates}-relation-changed')
    def changed(self):
        '''Only the leader should change the state to sign the request. '''
        # Get the global scoped conversation.
        conversation = self.conversation()
        if conversation.get_remote('ca'):
            conversation.set_state('{relation_name}.ca.available')
        if conversation.get_remote('server.cert'):
            conversation.set_state('{relation_name}.server.cert.available')
        if conversation.get_remote('client.cert'):
            conversation.set_state('{relation_name}.client.cert.available')

    @hook('{provides:tls-certificates}-relation-{broken,departed}')
    def broken_or_departed(self):
        '''Remove the states that were set.'''
        conversation = self.conversation()
        conversation.remove_state('{relation_name}.available')

    def get_ca(self):
        '''Return the certificate authority from the relation object.'''
        # Get the global scoped conversation.
        conversation = self.conversation()
        # Find the certificate authority by key, and return the value.
        return conversation.get_remote('ca')

    def get_client_cert(self):
        '''Return the client certificate and key from the relation object.'''
        conversation = self.conversation()
        client_cert = conversation.get_remote('client.cert')
        client_key = conversation.get_remote('client.key')
        return client_cert, client_key

    def get_server_cert(self):
        '''Return the server certificate and key from the relation objects.'''
        conversation = self.conversation()
        server_cert = conversation.get_remote('server.cert')
        server_key = conversation.get_remote('server.key')
        return server_cert, server_key

    def request_server_cert(self, cn, sans, cert_name):
        '''Set the CN, list of sans, and certifiicate name on the relation to
        request a server certificate.'''
        conversation = self.conversation()
        # A server certificate requires a CN, sans, and a certificate name.
        conversation.set_remote('common_name', cn)
        conversation.set_remote('sans', json.dumps(sans))
        conversation.set_remote('certificate_name', cert_name)
