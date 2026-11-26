import hashlib
import json

from ..exceptions import JWKError
from ..utils import base64url_encode, ensure_binary

# Required JWK members used to compute the RFC 7638 thumbprint, keyed by kty.
_THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
    "oct": ("k", "kty"),
}


def jwk_thumbprint(key_data, hash_alg=hashlib.sha256):
    """Compute the thumbprint of a JWK as specified by RFC 7638.

    Args:
        key_data (dict): The JWK to compute the thumbprint of.
        hash_alg (callable): A callable returning a hash object, e.g. hashlib.sha256

    Returns:
        str: The base64url encoded thumbprint of the key.
    """
    kty = key_data.get("kty")
    try:
        members = _THUMBPRINT_MEMBERS[kty]
    except KeyError:
        raise JWKError("Unable to compute a thumbprint for kty %r" % (kty,))

    canonical = {}
    for member in members:
        try:
            value = key_data[member]
        except KeyError:
            raise JWKError("Missing required JWK member %r for kty %r" % (member, kty))
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        canonical[member] = value

    # RFC 7638 section 3: the required members, in lexicographic order,
    # serialized to JSON with no whitespace.
    serialized = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    digest = hash_alg(serialized.encode("utf-8")).digest()
    return base64url_encode(digest).decode("utf-8")


class Key:
    """
    A simple interface for implementing JWK keys.
    """

    def __init__(self, key, algorithm):
        pass

    def sign(self, msg):
        raise NotImplementedError()

    def verify(self, msg, sig):
        raise NotImplementedError()

    def public_key(self):
        raise NotImplementedError()

    def to_pem(self):
        raise NotImplementedError()

    def to_dict(self):
        raise NotImplementedError()

    def thumbprint(self, hash_alg=hashlib.sha256):
        """Compute the thumbprint of this key as specified by RFC 7638.

        The thumbprint is a stable identifier for the key material: it is
        derived only from the required JWK members and is independent of
        any server-assigned "kid".

        Args:
            hash_alg (callable): A callable returning a hash object, e.g. hashlib.sha256

        Returns:
            str: The base64url encoded thumbprint of the key.
        """
        return jwk_thumbprint(self.to_dict(), hash_alg=hash_alg)

    def encrypt(self, plain_text, aad=None):
        """
        Encrypt the plain text and generate an auth tag if appropriate

        Args:
            plain_text (bytes): Data to encrypt
            aad (bytes, optional): Authenticated Additional Data if key's algorithm supports auth mode

        Returns:
            (bytes, bytes, bytes): IV, cipher text, and auth tag
        """
        raise NotImplementedError()

    def decrypt(self, cipher_text, iv=None, aad=None, tag=None):
        """
        Decrypt the cipher text and validate the auth tag if present
        Args:
            cipher_text (bytes): Cipher text to decrypt
            iv (bytes): IV if block mode
            aad (bytes): Additional Authenticated Data to verify if auth mode
            tag (bytes): Authentication tag if auth mode

        Returns:
            bytes: Decrypted value
        """
        raise NotImplementedError()

    def wrap_key(self, key_data):
        """
        Wrap the the plain text key data

        Args:
            key_data (bytes): Key data to wrap

        Returns:
            bytes: Wrapped key
        """
        raise NotImplementedError()

    def unwrap_key(self, wrapped_key):
        """
        Unwrap the the wrapped key data

        Args:
            wrapped_key (bytes): Wrapped key data to unwrap

        Returns:
            bytes: Unwrapped key
        """
        raise NotImplementedError()


class DIRKey(Key):
    def __init__(self, key_data, algorithm):
        self._key = ensure_binary(key_data)
        self._alg = algorithm

    def to_dict(self):
        return {
            "alg": self._alg,
            "kty": "oct",
            "k": base64url_encode(self._key),
        }
