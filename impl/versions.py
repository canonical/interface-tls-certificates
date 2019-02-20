import weakref


def negotiate(endpoint):
    """
    Given an Endpoint instance, populate all relations with the correct
    implementation for the maximum mutually supported protocol version.

    If the relation is currently using an older protocol version than
    is mutually supported, this will call `upgrade_protocol` on the
    new version, followed by `clear` on the old version.
    """
    protocols = {proto.VERSION: proto for proto in endpoint.PROTOCOLS}
    local_min_version = min(protocols.keys())
    local_max_version = max(protocols.keys())
    for relation in endpoint.relations:
        if getattr(relation, 'protocol', None):
            continue
        remote_max_version = (relation.joined_units.received['max-version'] or
                              local_min_version)
        current_version = (relation.to_publish['current-version'] or
                           local_min_version)
        # determine max common supported version
        new_version = min(local_max_version, remote_max_version)
        # publish the max version we support
        relation.to_publish['max-version'] = local_max_version
        if current_version != new_version:
            # upgrade protocol version
            old_protocol = protocols[current_version](relation)
            new_protocol = protocols[new_version](relation)
            new_protocol.upgrade_from(old_protocol)
            old_protocol.clear()
            relation.to_publish['current-version'] = new_version
            protocol = new_protocol
        else:
            protocol = protocols[current_version](relation)
        relation.protocol = protocol


class VersionedType(type):
    """
    Metaclass to ensure all subclasses define a VERSION attribute.
    """
    def __init__(cls, name, bases, nmspc):
        if 'VERSION' not in nmspc:
            raise TypeError(name + ' must specify VERSION')
        super().__init__(name, bases, nmspc)


class VersionedProtocol(metaclass=VersionedType):
    VERSION = None
    """
    Integer version number for this implementation.

    Must be set by subclasses.
    """

    def __init__(self, relation):
        self.relation = weakref.proxy(relation)

    @property
    def endpoint(self):
        return self.relation.endpoint

    def upgrade_protocol(self, old_protocol):
        """
        Upgrade to this protocol version from a previous one.

        Must be implemented by subclasses.
        """
        raise NotImplementedError()

    def clear(self):
        """
        Clear all data in this protocol version's format from the relation.

        Called automatically once the protocol has been upgraded.

        Should be implemented by subclasses.
        """
        pass
