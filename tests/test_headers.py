import json

import pytest

from jose import jwe, jws, jwt
from jose.exceptions import JOSEError, JWEError, JWEParseError, JWSError, JWTError
from jose.headers import PROTECTED_HEADER, RECIPIENT_UNPROTECTED_HEADER, SHARED_UNPROTECTED_HEADER, merge_headers
from jose.utils import base64url_decode, base64url_encode


class TestMergeHeaders:
    def test_single_protected_header_is_returned_as_dict(self):
        protected = {"alg": "dir", "enc": "A128GCM"}
        assert merge_headers(protected) == protected

    def test_missing_headers_are_optional(self):
        assert merge_headers(None, None, None) == {}

    def test_three_disjoint_headers_merge_in_order(self):
        protected = {"alg": "dir", "enc": "A128GCM"}
        shared = {"kid": "shared-key"}
        recipient = {"cty": "application/json"}
        merged = merge_headers(protected, shared, recipient)
        assert merged == {"alg": "dir", "enc": "A128GCM", "kid": "shared-key", "cty": "application/json"}

    @pytest.mark.parametrize(
        ("second", "third", "expected_locations"),
        [
            ({"alg": "A128KW"}, None, (PROTECTED_HEADER, SHARED_UNPROTECTED_HEADER)),
            (None, {"alg": "A128KW"}, (PROTECTED_HEADER, RECIPIENT_UNPROTECTED_HEADER)),
            (
                {"cty": "application/json"},
                {"cty": "text/plain"},
                (SHARED_UNPROTECTED_HEADER, RECIPIENT_UNPROTECTED_HEADER),
            ),
        ],
    )
    def test_duplicate_name_across_headers_names_both_sources(self, second, third, expected_locations):
        protected = {"alg": "dir", "enc": "A128GCM", "kid": "k0"}
        with pytest.raises(JOSEError) as excinfo:
            merge_headers(protected, second, third)
        message = str(excinfo.value)
        assert expected_locations[0] in message
        assert expected_locations[1] in message

    def test_non_object_header_is_rejected(self):
        with pytest.raises(JOSEError):
            merge_headers({"alg": "dir"}, ["not", "an", "object"])


class TestCriticalHeader:
    def test_message_without_crit_is_unaffected(self):
        # Legacy messages carry no critical extension and must still parse.
        assert merge_headers({"alg": "dir", "enc": "A128GCM"}) == {"alg": "dir", "enc": "A128GCM"}

    def test_understood_critical_parameter_in_protected_header_passes(self):
        protected = {"alg": "dir", "enc": "A128GCM", "kid": "key-1", "crit": ["kid"]}
        assert merge_headers(protected)["crit"] == ["kid"]

    def test_crit_must_be_a_non_empty_list(self):
        with pytest.raises(JOSEError):
            merge_headers({"alg": "dir", "crit": []})
        with pytest.raises(JOSEError):
            merge_headers({"alg": "dir", "crit": "kid"})

    def test_crit_entries_must_be_strings(self):
        with pytest.raises(JOSEError):
            merge_headers({"alg": "dir", "crit": [1]})

    def test_crit_cannot_contain_duplicates(self):
        with pytest.raises(JOSEError):
            merge_headers({"alg": "dir", "kid": "k", "crit": ["kid", "kid"]})

    def test_critical_parameter_must_exist_in_protected_header(self):
        with pytest.raises(JOSEError) as excinfo:
            merge_headers({"alg": "dir", "enc": "A128GCM", "crit": ["kid"]})
        assert "kid" in str(excinfo.value)

    def test_critical_parameter_in_unprotected_header_is_rejected(self):
        protected = {"alg": "dir", "crit": ["kid"], "kid": "k1"}
        with pytest.raises(JOSEError):
            merge_headers(protected, {"crit": ["kid"]})
        with pytest.raises(JOSEError):
            merge_headers(protected, None, {"crit": ["kid"]})

    def test_unregistered_critical_parameter_hard_fails(self):
        protected = {"alg": "dir", "http://example.com/ext": True, "crit": ["http://example.com/ext"]}
        with pytest.raises(JOSEError) as excinfo:
            merge_headers(protected)
        assert "not a registered" in str(excinfo.value)


def _compact_jwe(header, encrypted_key=b"", iv=b"0" * 12, ciphertext=b"", auth_tag=b""):
    encoded_header = base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    return b".".join(
        [
            encoded_header,
            base64url_encode(encrypted_key),
            base64url_encode(iv),
            base64url_encode(ciphertext),
            base64url_encode(auth_tag),
        ]
    )


class TestJweGate:
    def test_legacy_message_without_crit_still_decrypts(self):
        key = b"0123456789abcdef"
        token = jwe.encrypt(b"legacy payload", key, algorithm="dir", encryption="A128GCM")
        assert jwe.decrypt(token, key) == b"legacy payload"

    def test_declared_critical_extension_hard_fails(self):
        header = {"alg": "dir", "enc": "A128GCM", "http://example.com/ext": True, "crit": ["http://example.com/ext"]}
        token = _compact_jwe(header)
        with pytest.raises(JWEError):
            jwe.decrypt(token, b"0123456789abcdef")

    def test_understood_critical_parameter_is_accepted(self, monkeypatch):
        key = b"0123456789abcdef"

        original_encoded_header = jwe._encoded_header

        def encoded_header_with_crit(alg, enc, zip, cty, kid):
            encoded = original_encoded_header(alg, enc, zip, cty, kid)
            header = json.loads(base64url_decode(encoded))
            header["crit"] = ["kid"]
            return base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))

        # The auth tag covers the protected header (AAD), so inject the
        # "crit" member at serialization time rather than mutating a finished
        # token.
        monkeypatch.setattr(jwe, "_encoded_header", encoded_header_with_crit)
        token = jwe.encrypt(b"critical payload", key, algorithm="dir", encryption="A128GCM", kid="key-1")
        assert jwe.decrypt(token, key) == b"critical payload"

    def test_duplicate_member_inside_protected_header_is_parse_error(self):
        encoded = base64url_encode(b'{"alg":"dir","alg":"A128KW","enc":"A128GCM"}')
        token = b".".join([encoded, b"", base64url_encode(b"0" * 12), b"", b""])
        with pytest.raises(JWEParseError):
            jwe.decrypt(token, b"0123456789abcdef")


class TestJwsGate:
    def test_legacy_token_without_crit_still_verifies(self):
        token = jws.sign({"a": "b"}, "secret", algorithm="HS256")
        assert jws.verify(token, "secret", algorithms=["HS256"])

    def test_declared_critical_extension_hard_fails(self):
        header = {"alg": "HS256", "typ": "JWT", "http://example.com/ext": True, "crit": ["http://example.com/ext"]}
        token = jws.sign({"a": "b"}, "secret", headers=header, algorithm="HS256")
        with pytest.raises(JWSError):
            jws.verify(token, "secret", algorithms=["HS256"])

    def test_critical_failure_surfaces_as_jwt_error(self):
        header = {"alg": "HS256", "typ": "JWT", "http://example.com/ext": True, "crit": ["http://example.com/ext"]}
        token = jws.sign({"a": "b"}, "secret", headers=header, algorithm="HS256")
        with pytest.raises(JWTError):
            jwt.decode(token, "secret", algorithms=["HS256"])

    def test_duplicate_member_inside_protected_header_is_jws_error(self):
        encoded = base64url_encode(b'{"alg":"HS256","alg":"none"}')
        token = b".".join([encoded, base64url_encode(b"{}"), base64url_encode(b"sig")])
        with pytest.raises(JWSError):
            jws.verify(token, "secret", algorithms=["HS256"])
