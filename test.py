#!/usr/bin/env python3

import unittest
import hashlib
import multihash
import pyblake2
import sha3


class TestMultiHash(unittest.TestCase):
    def encode(self, hash_name, payload, expected_code):
        multihasher = multihash.new(hash_name)
        if hash_name == 'blake2s':
            reference_hasher = pyblake2.blake2s()
        elif hash_name == 'blake2b':
            reference_hasher = pyblake2.blake2b()
        elif hash_name == 'sha3':
            reference_hasher = hashlib.new('sha3_256')
        else:
            reference_hasher = hashlib.new(hash_name)
        multihasher.update(payload.encode('utf8'))
        reference_hasher.update(payload.encode('utf8'))
        self.assertTrue(multihasher.hexdigest().endswith(
            reference_hasher.hexdigest()))
        self.assertEqual(multihasher.digest()[0], expected_code)
        self.assertEqual(multihasher.digest()[1], len(reference_hasher.digest()))

    def test_encode(self):
        hashes = {'sha1': 0x11,
                  'sha256': 0x12,
                  'sha512': 0x13,
                  'sha3': 0x14,
                  'blake2b': 0x40,
                  'blake2s': 0x41}
        for hash_name, hash_code in hashes.items():
            with(self.subTest(hash=hash_name)):
                for payload in 'foo', 'bar', '':
                    with(self.subTest(payload=payload)):
                        self.encode(hash_name, payload, hash_code)

    def test_unexisting(self):
        with self.assertRaises(ValueError):
            multihash.new('foo').encode('42')

    def test_named_constructors(self):
        self.assertEqual(multihash.sha1().known_hash,
                         multihash.new('sha1').known_hash)
        self.assertEqual(multihash.sha3().known_hash,
                         multihash.new('sha3').known_hash)
        self.assertEqual(multihash.blake2s().known_hash,
                         multihash.new('blake2s').known_hash)

    def test_copy(self):
        mh1 = multihash.new('sha3')
        mh1.update(b'foo')
        mh2 = mh1.copy()
        self.assertEqual(mh1.hexdigest(), mh2.hexdigest())
        mh2.update(b'bar')
        self.assertNotEqual(mh1.hexdigest(), mh2.hexdigest())

if __name__ == '__main__':
    unittest.main()
