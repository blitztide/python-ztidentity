# BSD 2-Clause License
#
# Copyright (c) 2023, Open DIS
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import hashlib
from ztidentity.salsa20 import salsa20_xor
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

ZT_IDENTITY_GEN_MEMORY = 2 * 1024 * 1024  # 2M block


def get_address(digest: bytes) -> bytes:
    """
    Takes the digest bytes and returns the ZT Address
    """
    if len(digest) != 64:
        raise ValueError("Digest must be 64 bytes")

    address = 0
    for i in range(59, 64):
        address <<= 8
        address |= digest[i]

    return address.to_bytes(5, 'big')


def check_hash(hash: bytes) -> bool:
    """
    Checks a hash to ensure correctness
    Checking:
        * Size ( has to be 64 bytes )
        * First byte is less than 17 ( Proof of work )
        * Address is not a reserved address
    """
    # Ensure hash is correct length
    if len(hash) != 64:
        return False

    # Ensure proof of work
    first_byte_less_than = 17
    if hash[0] > first_byte_less_than:
        return False

    # Ensure not a reserved address
    if hash[59] == 0xFF:
        return False

    # Valid address
    return True


def ComputeHash(public_key: bytes) -> bytes:
    """
    Memory Hard Hash computation
    This is to slow down attacker generation of addresses
    """
    s512 = bytearray(hashlib.sha512(public_key).digest())
    genmem = bytearray(ZT_IDENTITY_GEN_MEMORY)

    s20key = bytes(s512[0:32])
    s20ctr = bytearray(16)
    s20ctr[0:8] = s512[32:40]

    s20ctri = 0

    # first block
    genmem[0:64] = salsa20_xor(
        genmem[0:64],
        bytes(s20ctr),
        s20key
    )
    s20ctri += 1

    for i in range(64, ZT_IDENTITY_GEN_MEMORY, 64):
        s20ctr[8:16] = s20ctri.to_bytes(8, "little")
        genmem[i:i+64] = salsa20_xor(
            genmem[i-64:i],
            bytes(s20ctr),
            s20key
        )
        s20ctri += 1

    tmp = bytearray(8)
    i = 0

    while i < ZT_IDENTITY_GEN_MEMORY:
        idx1 = (int.from_bytes(genmem[i:i+8], "big") & 7) * 8
        i += 8

        idx2 = (
            int.from_bytes(genmem[i:i+8], "big")
            % (ZT_IDENTITY_GEN_MEMORY // 8)
        ) * 8
        i += 8

        gm = genmem[idx2:idx2+8]
        d = s512[idx1:idx1+8]

        tmp[:] = gm
        genmem[idx2:idx2+8] = d
        s512[idx1:idx1+8] = tmp

        s20ctr[8:16] = s20ctri.to_bytes(8, "little")
        s512[:] = salsa20_xor(s512, bytes(s20ctr), s20key)
        s20ctri += 1

    return bytes(s512)


def GenerateKeys() -> (bytes, bytes):
    """
    Generate an ED25519 key and X25519 (Curve25519) key using PyCryptodome.
    Convert each to bytes then
    Concatenate them both (ED + X) for public and private keys.
    Return as bytes.
    """

    # Generate Ed25519 key pair
    # TODO make this deterministic via get_random_bytes
    ed_private_key = ECC.generate(curve='Ed25519')
    ed_public_key = ed_private_key.public_key()

    # Export Ed25519 keys as raw 32-byte bytes
    ed_private_bytes = ed_private_key.d.to_bytes(32, 'big')
    ed_public_bytes = ed_public_key.pointQ.x.to_bytes(32, 'big')

    # Generate X25519 (Curve25519) key pair
    # PyCryptodome doesn't have a direct X25519 object; we can use raw bytes
    x_private_bytes = get_random_bytes(32)
    x_private_key = ECC.construct(seed=x_private_bytes, curve="Curve25519")

    # Compute Curve25519 public key via scalar multiplication with base point
    x_public_key = x_private_key.public_key()
    x_public_bytes = x_public_key.pointQ.x.to_bytes(32, 'big')

    # Concatenate keys (ED + X)
    public_key = ed_public_bytes + x_public_bytes
    private_key = ed_private_bytes + x_private_bytes

    return public_key, private_key


class ZeroTierIdentity():
    address = None
    public_key = None
    private_key = None
    _digest = None  # Stored only for Unit Testing

    def __init__(self):
        valid_key = False
        attempt = 1
        while not valid_key:
            print(f"Attempt: {attempt}")
            pub, priv = GenerateKeys()
            digest = ComputeHash(pub)
            valid_hash = check_hash(digest)
            address = get_address(digest)
            if valid_hash and address != b"0000000000":
                valid_key = True
            attempt += 1

        self.address = address
        self.public_key = pub
        self.private_key = priv
        self._digest = digest

    def PrivateKeyString(self):
        return "{:10s}:0:{}:{}".format(
            self.address.hex(),
            self.public_key.hex(),
            self.private_key.hex())

    def PublicKeyString(self):
        return "{:10s}:0:{}".format(
            self.address.hex(), self.public_key.hex())

    def IDString(self):
        return "{:10s}".format(
            self.address.hex())

    def ID(self):
        return self.address

    def PrivateKey(self):
        return self.private_key

    def PublicKey(self):
        return self.public_key
