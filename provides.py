import json

from charms.reactive import hook
from charms.reactive import scopes
from charms.reactive import RelationBase


class TlsProvides(RelationBase):
    '''The class that provides a TLS interface other units.'''
    scope = scopes.UNIT

    @hook('{provides:tls-certificates}-relation-joined')
    def joined(self):
        '''When a unit joins, set the available state.'''
        # Get the conversation scoped to the unit name.
        conversation = self.conversation()
        conversation.set_state('{relation_name}.available')

    @hook('{provides:tls-certificates}-relation-changed')
    def changed(self):
        '''When a unit relation changes, check for a server certificate request
        and set the server.cert.requested state.'''
        conversation = self.conversation()
        cn = conversation.get_remote('common_name')
        sans = conversation.get_remote('sans')
        name = conversation.get_remote('certificate_name')
        requests = conversation.get_remote('cert_requests')
        # When the relation has all three values set the server.cert.requested.
        if (cn and sans and name) or requests:
            conversation.set_state('{relation_name}.server.cert.requested')

    @hook('{provides:tls-certificates}-relation-{broken,departed}')
    def broken_or_departed(self):
        '''Remove the available state from the unit as we are leaving.'''
        conversation = self.conversation()
        conversation.remove_state('{relation_name}.available')

    def set_ca(self, certificate_authority):
        '''Set the CA on all the conversations in the relation data.'''
        # Iterate over all conversations of this type.
        for conversation in self.conversations():
            # All the clients get the same CA, so send it to them.
            conversation.set_remote(data={'ca': certificate_authority})

    def set_chain(self, chain):
        '''Set the chain on all the conversations in the relation data.'''
        # Iterate over all conversations of this type.
        for conversation in self.conversations():
            # All the clients get the same chain, so send it to them.
            conversation.set_remote(data={'chain': chain})

    def set_client_cert(self, cert, key):
        '''Set the client cert and key on the relation data.'''
        # Iterate over all conversations of this type.
        for conversation in self.conversations():
            client = {}
            client['client.cert'] = cert
            client['client.key'] = key
            # Send the client cert and key to the unit using the conversation.
            conversation.set_remote(data=client)

    def set_server_cert(self, scope, cert, key):
        '''Set the server cert and key on the relation data.'''
        # Get the coversation scoped to the unit.
        conversation = self.conversation(scope)
        server = {}
        # The scope is the unit name, replace the slash with underscore.
        name = scope.replace('/', '_')
        # Prefix the key with name so each unit can get a unique cert and key.
        server['{0}.server.cert'.format(name)] = cert
        server['{0}.server.key'.format(name)] = key
        # Send the server cert and key to the unit using the conversation.
        conversation.set_remote(data=server)
        # Remove the server.cert.requested state as it is no longer needed.
        conversation.remove_state('{relation_name}.server.cert.requested')

    def set_server_multicerts(self, scope):
        conversation = self.conversation(scope)
        multi_certs = conversation.get_local('multi_certs')
        conversation.set_remote(
            'processed_requests',
            json.dumps(multi_certs, sort_keys=True))
        conversation.remove_state('{relation_name}.server.cert.requested')

    def add_server_cert(self, scope, cn, cert, key):
        '''
            'client_0': {
                'admin': {
                    'cert': cert
                    'key': key}}
        '''
        conversation = self.conversation(scope)
        # The scope is the unit name, replace the slash with underscore.
        name = scope.replace('/', '_')
        multi_certs = conversation.get_local('multi_certs')
        if multi_certs:
            multi_certs[cn] = {
                'cert': cert,
                'key': key}

        else:
            multi_certs = {
                cn: {
                    'cert': cert,
                    'key': key}}

        conversation.set_local('multi_certs', multi_certs)

    def get_server_requests(self):
        '''One provider can have many requests to generate server certificates.
        Return a map of all server request objects indexed by the scope
        which is essentially unit name.'''
        request_map = {}
        for conversation in self.conversations():
            scope = conversation.scope
            request = {}
            request['common_name'] = conversation.get_remote('common_name')
            sans = conversation.get_remote('sans')
            if sans:
                request['sans'] = json.loads(sans)
            request['certificate_name'] = conversation.get_remote('certificate_name')  # noqa
            cert_requests = conversation.get_remote('cert_requests')
            if cert_requests:
                request['cert_requests'] = json.loads(cert_requests)
            # Create a map indexed by scope.
            request_map[scope] = request
        return request_map
