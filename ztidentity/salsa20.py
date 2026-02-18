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

import struct


def _rotl32(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def _salsa20_core(counter, key):
    """
    Salsa20 core producing 64-byte keystream.
    counter: 16 bytes
    key: 32 bytes
    """
    constants = b"expand 32-byte k"

    def u32(x):
        return struct.unpack("<I", x)[0]

    state = [
        u32(constants[0:4]),
        u32(key[0:4]),
        u32(key[4:8]),
        u32(key[8:12]),
        u32(key[12:16]),
        u32(constants[4:8]),
        u32(counter[0:4]),
        u32(counter[4:8]),
        u32(counter[8:12]),
        u32(counter[12:16]),
        u32(constants[8:12]),
        u32(key[16:20]),
        u32(key[20:24]),
        u32(key[24:28]),
        u32(key[28:32]),
        u32(constants[12:16]),
    ]

    x = state[:]

    for _ in range(10):  # 20 rounds
        # column rounds
        x[4] ^= _rotl32((x[0] + x[12]) & 0xffffffff, 7)
        x[8] ^= _rotl32((x[4] + x[0]) & 0xffffffff, 9)
        x[12] ^= _rotl32((x[8] + x[4]) & 0xffffffff, 13)
        x[0] ^= _rotl32((x[12] + x[8]) & 0xffffffff, 18)

        x[9] ^= _rotl32((x[5] + x[1]) & 0xffffffff, 7)
        x[13] ^= _rotl32((x[9] + x[5]) & 0xffffffff, 9)
        x[1] ^= _rotl32((x[13] + x[9]) & 0xffffffff, 13)
        x[5] ^= _rotl32((x[1] + x[13]) & 0xffffffff, 18)

        x[14] ^= _rotl32((x[10] + x[6]) & 0xffffffff, 7)
        x[2] ^= _rotl32((x[14] + x[10]) & 0xffffffff, 9)
        x[6] ^= _rotl32((x[2] + x[14]) & 0xffffffff, 13)
        x[10] ^= _rotl32((x[6] + x[2]) & 0xffffffff, 18)

        x[3] ^= _rotl32((x[15] + x[11]) & 0xffffffff, 7)
        x[7] ^= _rotl32((x[3] + x[15]) & 0xffffffff, 9)
        x[11] ^= _rotl32((x[7] + x[3]) & 0xffffffff, 13)
        x[15] ^= _rotl32((x[11] + x[7]) & 0xffffffff, 18)

        # row rounds
        x[1] ^= _rotl32((x[0] + x[3]) & 0xffffffff, 7)
        x[2] ^= _rotl32((x[1] + x[0]) & 0xffffffff, 9)
        x[3] ^= _rotl32((x[2] + x[1]) & 0xffffffff, 13)
        x[0] ^= _rotl32((x[3] + x[2]) & 0xffffffff, 18)

        x[6] ^= _rotl32((x[5] + x[4]) & 0xffffffff, 7)
        x[7] ^= _rotl32((x[6] + x[5]) & 0xffffffff, 9)
        x[4] ^= _rotl32((x[7] + x[6]) & 0xffffffff, 13)
        x[5] ^= _rotl32((x[4] + x[7]) & 0xffffffff, 18)

        x[11] ^= _rotl32((x[10] + x[9]) & 0xffffffff, 7)
        x[8] ^= _rotl32((x[11] + x[10]) & 0xffffffff, 9)
        x[9] ^= _rotl32((x[8] + x[11]) & 0xffffffff, 13)
        x[10] ^= _rotl32((x[9] + x[8]) & 0xffffffff, 18)

        x[12] ^= _rotl32((x[15] + x[14]) & 0xffffffff, 7)
        x[13] ^= _rotl32((x[12] + x[15]) & 0xffffffff, 9)
        x[14] ^= _rotl32((x[13] + x[12]) & 0xffffffff, 13)
        x[15] ^= _rotl32((x[14] + x[13]) & 0xffffffff, 18)

    out = []
    for i in range(16):
        out.append((x[i] + state[i]) & 0xffffffff)

    return b"".join(struct.pack("<I", v) for v in out)


def salsa20_xor(data: bytes, counter: bytes, key: bytes) -> bytes:
    ks = _salsa20_core(counter, key)
    return bytes(a ^ b for a, b in zip(data, ks))
