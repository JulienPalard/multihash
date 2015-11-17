#!/usr/bin/env python3

"""Multihash drop-in replacement for hashlib.
"""
import struct
from enum import Enum
import hashlib
import sha3


class Known_Hashes(Enum):
    """Currently supported hashes, from:
    https://github.com/jbenet/multihash/blob/master/hashtable.csv
    """
    sha1 = 0x11
    sha256 = 0x12
    sha512 = 0x13
    sha3 = 0x14
    blake2b = 0x40
    blake2s = 0x41


class _Hash(object):
    """Drop in replacement for a hashlib hash object, prefixing digest
    and hexdigest with multihash header.
    """
    def __init__(self, known_hash, data=b''):
        self.known_hash = known_hash
        if known_hash == Known_Hashes.blake2b:
            from pyblake2 import blake2b
            self.implem = blake2b()
        elif known_hash == Known_Hashes.blake2s:
            from pyblake2 import blake2s
            self.implem = blake2s()
        elif known_hash == Known_Hashes.sha3:
            self.implem = hashlib.new('sha3_256')
        else:
            self.implem = hashlib.new(known_hash.name, data)

    def update(self, arg):
        """Update the hash object with the bytes in arg. Repeated calls
        are equivalent to a single call with the concatenation of all
        the arguments.
        """
        self.implem.update(arg)

    def digest(self):
        """Return the digest of the bytes passed to the update() method
        so far, prefixed by the two-bytes multihash header.
        """
        digest = self.implem.digest()
        return struct.pack("BB", self.known_hash.value, len(digest)) + digest

    def hexdigest(self):
        """Like digest() except the multihash header and its digest digest are
        returned as a unicode object, containing only hexadecimal digits.
        """
        return r"{hash:x}{size:x}{digest}".format(
            hash=self.known_hash.value,
            size=len(self.implem.digest()),
            digest=self.implem.hexdigest())

    def copy(self):
        """Return a copy (clone) of the multihash object. This can be used to
        efficiently compute the digests of strings that share a common
        initial substring.
        """
        clone = _Hash(self.known_hash)
        clone.implem = self.implem.copy()
        return clone


globals().update({known_hash.name: _Hash(known_hash).copy for
                  known_hash in Known_Hashes})


def new(name, data=b''):
    """new(name, data=b'') - Return a new multihash object using the named
    algorithm; optionally initialized with data (which must be bytes).
    """
    try:
        return _Hash(Known_Hashes[name], data)
    except KeyError as err:
        raise ValueError('unsupported hash type ' + name) from err
