import hashlib

import pytest

from jose import jwk
from jose.backends import AESKey, ECKey, HMACKey, RSAKey
from jose.backends.base import Key
from jose.exceptions import JWKError

hmac_key = {
    "kty": "oct",
    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
    "use": "sig",
    "alg": "HS256",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
}

rsa_key = {
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB",
}

ec_key = {
    "kty": "EC",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "crv": "P-521",
    "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
}


class TestJWK:
    def test_interface(self):
        key = jwk.Key("key", "ALG")

        with pytest.raises(NotImplementedError):
            key.sign("")

        with pytest.raises(NotImplementedError):
            key.verify("", "")

    @pytest.mark.skipif(RSAKey is None, reason="RSA is not available")
    def test_invalid_hash_alg(self):
        with pytest.raises(JWKError):
            key = HMACKey(hmac_key, "RS512")

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, "HS512")

        with pytest.raises(JWKError):
            key = ECKey(ec_key, "RS512")  # noqa: F841

    @pytest.mark.skipif(RSAKey is None, reason="RSA is not available")
    def test_invalid_jwk(self):
        with pytest.raises(JWKError):
            key = HMACKey(rsa_key, "HS256")

        with pytest.raises(JWKError):
            key = RSAKey(hmac_key, "RS256")

        with pytest.raises(JWKError):
            key = ECKey(rsa_key, "ES256")  # noqa: F841

    @pytest.mark.skipif(RSAKey is None, reason="RSA is not available")
    def test_RSAKey_errors(self):
        rsa_key = {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB",
        }

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, "HS256")

        rsa_key = {
            "kty": "oct",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB",
        }

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, "RS256")  # noqa: F841

    def test_construct_from_jwk(self):
        hmac_key = {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "alg": "HS256",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        }

        key = jwk.construct(hmac_key)
        assert isinstance(key, jwk.Key)

    def test_construct_EC_from_jwk(self):
        key = ECKey(ec_key, algorithm="ES512")
        assert isinstance(key, jwk.Key)

    def test_construct_from_jwk_missing_alg(self):
        hmac_key = {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        }

        with pytest.raises(JWKError):
            key = jwk.construct(hmac_key)

        with pytest.raises(JWKError):
            key = jwk.construct("key", algorithm="NONEXISTENT")  # noqa: F841

    def test_get_key(self):
        hs_key = jwk.get_key("HS256")
        assert hs_key == HMACKey
        assert issubclass(hs_key, Key)
        if RSAKey is not None:
            assert issubclass(jwk.get_key("RS256"), Key)
        assert issubclass(jwk.get_key("ES256"), Key)

        assert jwk.get_key("NONEXISTENT") is None

    @pytest.mark.skipif(AESKey is None, reason="No AES provider")
    def test_get_aes_key(self):
        assert issubclass(jwk.get_key("A256CBC-HS512"), Key)

    def test_register_key(self):
        assert jwk.register_key("ALG", jwk.Key)
        assert jwk.get_key("ALG") == jwk.Key

        with pytest.raises(TypeError):
            assert jwk.register_key("ALG", object)


# JWK and expected thumbprint from RFC 7638, section 3.1.
rfc7638_key = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_"
        "BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_"
        "FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI"
        "4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
rfc7638_thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


class TestThumbprint:
    @pytest.mark.skipif(RSAKey is None, reason="RSA is not available")
    def test_rfc7638_example(self):
        key = jwk.construct(rfc7638_key, algorithm="RS256")
        assert key.thumbprint() == rfc7638_thumbprint

    def test_hmac_thumbprint(self):
        key = jwk.construct(hmac_key, algorithm="HS256")
        expected = jwk.jwk_thumbprint(hmac_key)
        assert key.thumbprint() == expected

    def test_thumbprint_ignores_kid(self):
        # The thumbprint identifies the key material, not the server-assigned
        # kid, so two JWKs with different kids but the same material match.
        other = dict(hmac_key, kid="some-other-kid")
        assert jwk.jwk_thumbprint(other) == jwk.jwk_thumbprint(hmac_key)

    def test_thumbprint_hash_alg(self):
        thumbprint = jwk.jwk_thumbprint(hmac_key, hash_alg=hashlib.sha512)
        assert thumbprint != jwk.jwk_thumbprint(hmac_key)
        assert len(thumbprint) == 86  # base64url of 64 bytes, no padding

    def test_thumbprint_unknown_kty(self):
        with pytest.raises(JWKError):
            jwk.jwk_thumbprint({"kty": "unknown"})

    def test_thumbprint_missing_member(self):
        with pytest.raises(JWKError):
            jwk.jwk_thumbprint({"kty": "oct"})


class TestGetKeyByThumbprint:
    @pytest.mark.skipif(RSAKey is None, reason="RSA is not available")
    def test_select_from_jwk_set(self):
        jwk_set = {"keys": [hmac_key, rfc7638_key]}
        assert jwk.get_key_by_thumbprint(jwk_set, rfc7638_thumbprint) == rfc7638_key

    @pytest.mark.skipif(RSAKey is None, reason="RSA is not available")
    def test_select_from_json_string(self):
        import json

        jwk_set = json.dumps({"keys": [hmac_key, rfc7638_key]})
        assert jwk.get_key_by_thumbprint(jwk_set, rfc7638_thumbprint) == rfc7638_key

    def test_select_key_instance(self):
        key = jwk.construct(hmac_key, algorithm="HS256")
        assert jwk.get_key_by_thumbprint([key], key.thumbprint()) is key

    def test_select_single_jwk(self):
        thumbprint = jwk.jwk_thumbprint(hmac_key)
        assert jwk.get_key_by_thumbprint(hmac_key, thumbprint) == hmac_key

    def test_no_match(self):
        with pytest.raises(JWKError):
            jwk.get_key_by_thumbprint({"keys": [hmac_key]}, "does-not-match")
