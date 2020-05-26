# Copyright (c) 2020 Pieter Wuille
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native Python MuHash3072 implementation."""

import hashlib

def modinv(a, n):
    """Compute the modular inverse of a modulo n."""
    t1, t2 = 0, 1
    r1, r2 = n, a
    while r2 != 0:
        q = r1 // r2
        t1, t2 = t2, t1 - q * t2
        r1, r2 = r2, r1 - q * r2
    if r1 > 1:
        return None
    if t1 < 0:
        t1 += n
    return t1

def rot32(v, bits):
    """Rotate the 32-bit value v left by bits bits."""
    return ((v << bits) & 0xffffffff) | (v >> (32 - bits))

def chacha20_doubleround(s):
    """Apply a ChaCha20 double round to 16-element state array s."""
    for a, b, c, d in ((0, 4,  8, 12), (1, 5,  9, 13), (2, 6, 10, 14), (3, 7, 11, 15), (0, 5, 10, 15), (1, 6, 11, 12), (2, 7,  8, 13), (3, 4,  9, 14)):
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = rot32(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = rot32(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = rot32(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = rot32(s[b] ^ s[c], 7)

def chacha20_32_to_384(key32):
    """Specialized ChaCha20 implementation with 32-byte key, 0 IV, 384-byte output."""
    init = [1634760805, 857760878, 2036477234, 1797285236] + [0] * 12
    for i in range(8):
        init[4 + i] = int.from_bytes(key32[4*i:4*(i+1)], 'little')
    out = bytearray()
    for pos in range(6):
        init[12] = pos
        s = list(init)
        for rnd in range(10):
            chacha20_doubleround(s)
        for i in range(16):
            out.extend(((s[i] + init[i]) & 0xffffffff).to_bytes(4, 'little'))
    return bytes(out)

def data_to_num3072(data):
    """Map a byte array data to a 3072-bit number."""
    key32 = hashlib.sha512(data).digest()[0:32]
    bytes384 = chacha20_32_to_384(key32)
    return int.from_bytes(bytes384, 'little')

class MuHash3072:
    """Class representing the MuHash3072 computation of a set."""

    MODULUS = 2**3072 - 1103717

    def __init__(self):
        """Initialize for an empty set."""
        self.numerator = 1
        self.denominator = 1

    def insert(self, data):
        """Insert a byte array data in the set."""
        self.numerator = (self.numerator * data_to_num3072(data)) % self.MODULUS

    def remove(self, data):
        """Remove a byte array from the set."""
        self.denominator = (self.denominator * data_to_num3072(data)) % self.MODULUS

    def digest(self):
        """Extract the final hash. Does not modify this object."""
        val = (self.numerator * modinv(self.denominator, self.MODULUS)) % self.MODULUS
        bytes384 = val.to_bytes(384, 'little')
        return hashlib.sha512(bytes384).digest()[0:32]
