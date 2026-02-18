import pytest
import ztidentity
from unittest.mock import patch


class TestZTIdentity():
    # These are all generated manually using zerotier-idtool generate
    valid_identities = [
        "1c41190849:0:b511c983f3e51d47f2367398930038a19b2c81037fbfe151713ef42e6600717f5593da8ef7067b803f2f621c1c45b3f048681ca2877b92b632c911bde394c37c:dcbf724b1209e0869e9118d20efe8d67e10865569aaf302867bd9dfbf22ed6f52b2eb1f027f061273bdf3be3000dad5cdb0d0bf347cc18028666f2157eeefdf4",
        "d228986ed9:0:2b1e61d2ca8db30e86665b278fe501752a39dc2dacd367de13ee49c5c047d21a05d0b619faa5f1d15dd8c9f89d331002e27ee771586577214c1e4b46f2a67a1d:22752b6bbddc40ef9e0f5de5eaebce1a49d3359397eef411dd8eabc8d0db1b9626b9b29172a2509a9e991593b00e28094d51410893c4e2361c59b484ce395d23",
        "468fbc3bb8:0:fb2dfd593a8a5b47d7cfba3e5c7e5f64c271358e2810b4791925fb6094927c74b7e5ef10b57e8d1d7174ff5463ffe70cec84c6719c8bd07dec1f34f6a03b068f:6f7f7411685ec1d4ab9859d8a3782ee7599088e6ece4d2aa28527d3c8da429f62165489be070f470830e518d0759a4e98a3fa0419f30417b3c6232e4bc80eb28"
        ]

    valid_addresses = [
        "a029f6e763:0b43b6553058f1db20f43362e190b4e8e193ed16d5c476d76d9ed6220f85def36a98b874c272f552b6448d186386e8c498e675ee2371308d0e20fca029f6e763",
        "6d44774a4d:01c0a9a0d9c7019b84c42fda8e943546f939f87e26dfee77978f02d018e468e36241f47f600b3a78da8b761855b90d7f72bbf2e78e25c8220bbb7f6d44774a4d",
        "b30647bdb2:0c4ede8a2cab510d971a7d5da56dafb8dddbb598f62b8eaa7589a5cb5705441fcbc05b84322f7d47e4821b5b67367dffa5c0e3598f92061548c057b30647bdb2"
        ]

    # These values have been calculated manually and verified
    valid_digests = [
        "deaa5a188fe46650477c7893893836ee7ca0ec34dfd9d6a191b32a334aface5e9786ab8be3fc562b568f4a9b98801f692c622f85ed01b8d175932dd9ec367666:04fffedf16a9fc9bf7bbebebc72d70e10912debb9992dcdfb9fa96a100fac5ef495b7bd3e5f0dc8b2067784c6eb74ef2a3e91e7d61c506d5aee06efd3986528d",
        "4e884cc4b7ab15349e1122521a0743e7f23812240ab7f2897f4cb7c7d91683642e39e2be5ce7f2e4d0f7455ca6dab811ed908c840f2982624bc17ed369b71bae:05338c36da2f8484e43a9835b1343036e10b2c4d130f4e26e0888fa0b0eb54ebf7d04ee62efd3d48b92eb99861e2569187eb23cfdffe51e99de894cca93fa65a",
        "9b62bd067840cfeef1c16eb714d6339cda6b763d648af0ff7c86826a7006e41eb2d4cdee2de4ebe3d9a0a39cd9abc595e93c7de03928aa37220d52fc30757bfb:03d0e47cbeb4ac4c5f3a80f2dfaa1234221504de1a31b016d6c25d27ea9fbf6a97f02ef9a01ae819924dfcdb06ec20cdd63ff427baae79a34f514267de07ef49"
        ]

    @pytest.fixture
    def random(self):
        """
        Patch randomness to produce deterministic results
        """
        with patch("ztidentity.get_random_bytes") as gr:
            gr.return_value = b'h1\x806\x80\x1c\xb4\xf8\xc1\xaf\x01\xa8\xe3\xc4\x0c\x10\xd6\xe1\x96\x1aY\xe0c\xd5\xf6\xc7HF\x9b?\xf0\xa1'
            yield gr

    def test_genkeys(self):
        (public_key, private_key) = ztidentity.GenerateKeys()

        # ensure key lengths are correct
        assert len(public_key) == 64
        assert len(private_key) == 64

        # Ensure types
        assert isinstance(public_key, bytes)
        assert isinstance(private_key, bytes)

    def test_init(self, random):
        # Ensure this doesn't raise Exceptions
        x = ztidentity.ZeroTierIdentity()

        # Check values returned
        assert isinstance(x.ID(), bytes)
        assert len(x.ID()) == 5

        assert isinstance(x.PrivateKey(), bytes)
        assert len(x.PrivateKey()) == 64

        assert isinstance(x.PublicKey(), bytes)
        assert len(x.PublicKey()) == 64

        assert isinstance(x.IDString(), str)
        assert len(x.IDString()) == 10

        assert isinstance(x.PublicKeyString(), str)
        assert len(x.PublicKeyString()) == 141

        assert isinstance(x.PrivateKeyString(), str)
        assert len(x.PrivateKeyString()) == 270

    def test_get_address(self):
        # Set digests and expected addresses
        for identity in self.valid_addresses:
            address, digest = identity.split(":")
            assert ztidentity.get_address(
                bytes.fromhex(digest)) == bytes.fromhex(address)

        # Ensure length check
        with pytest.raises(ValueError):
            ztidentity.get_address(b"00"*50)

    def test_compute_hash(self):
        for identity in self.valid_digests:
            pub_key, digest = identity.split(":")
            test_digest = ztidentity.ComputeHash(bytes.fromhex(pub_key))
            assert test_digest == bytes.fromhex(digest)

    def test_check_hash(self):
        # Test empty hash
        test_hash = b""
        assert not ztidentity.check_hash(test_hash)

        # Check less than 17
        test_hash = b"\x03" * 64
        assert ztidentity.check_hash(test_hash)

        # Check reserved address
        test_hash = b"\x03"*59 + b"\xFF" + b"\x03" * 4
        assert test_hash[59] == 0xff
        assert not ztidentity.check_hash(test_hash)
