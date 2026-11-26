import hashlib
import json

try:
    from collections.abc import Mapping
except ImportError:
    from collections import Mapping

from jose.backends.base import Key, jwk_thumbprint
from jose.constants import ALGORITHMS
from jose.exceptions import JWKError

try:
    from jose.backends import RSAKey  # noqa: F401
except ImportError:
    pass

try:
    from jose.backends import ECKey  # noqa: F401
except ImportError:
    pass

try:
    from jose.backends import AESKey  # noqa: F401
except ImportError:
    pass

try:
    from jose.backends import DIRKey  # noqa: F401
except ImportError:
    pass

try:
    from jose.backends import HMACKey  # noqa: F401
except ImportError:
    pass


def get_key(algorithm):
    if algorithm in ALGORITHMS.KEYS:
        return ALGORITHMS.KEYS[algorithm]
    elif algorithm in ALGORITHMS.HMAC:  # noqa: F811
        return HMACKey
    elif algorithm in ALGORITHMS.RSA:
        from jose.backends import RSAKey  # noqa: F811

        return RSAKey
    elif algorithm in ALGORITHMS.EC:
        from jose.backends import ECKey  # noqa: F811

        return ECKey
    elif algorithm in ALGORITHMS.AES:
        from jose.backends import AESKey  # noqa: F811

        return AESKey
    elif algorithm == ALGORITHMS.DIR:
        from jose.backends import DIRKey  # noqa: F811

        return DIRKey
    return None


def register_key(algorithm, key_class):
    if not issubclass(key_class, Key):
        raise TypeError("Key class is not a subclass of jwk.Key")
    ALGORITHMS.KEYS[algorithm] = key_class
    ALGORITHMS.SUPPORTED.add(algorithm)
    return True


def construct(key_data, algorithm=None):
    """
    Construct a Key object for the given algorithm with the given
    key_data.
    """

    # Allow for pulling the algorithm off of the passed in jwk.
    if not algorithm and isinstance(key_data, dict):
        algorithm = key_data.get("alg", None)

    if not algorithm:
        raise JWKError("Unable to find an algorithm for key")

    key_class = get_key(algorithm)
    if not key_class:
        raise JWKError("Unable to find an algorithm for key")
    return key_class(key_data, algorithm)


def get_key_by_thumbprint(keys, thumbprint, hash_alg=hashlib.sha256):
    """Select the key from a JWK set matching the given RFC 7638 thumbprint.

    Unlike a "kid", which is assigned by the server and may be shared by
    several keys during rotation, a thumbprint is computed from the key
    material itself and therefore identifies exactly one key.

    Args:
        keys: A JWK set (a dict with a "keys" member or its JSON string
            representation), an individual JWK, or an iterable of JWK dicts
            and/or Key instances.
        thumbprint (str): The base64url encoded thumbprint to match.
        hash_alg (callable): A callable returning a hash object, e.g. hashlib.sha256

    Returns:
        The matching key, as a JWK dict or Key instance.

    Raises:
        JWKError: If no key matches the given thumbprint.
    """
    if isinstance(keys, str):
        keys = json.loads(keys)

    if isinstance(keys, Mapping):
        if "keys" in keys:
            # JWK Set per RFC 7517
            keys = keys["keys"]
        else:
            # Individual JWK per RFC 7517
            keys = (keys,)

    for key in keys:
        if isinstance(key, Key):
            candidate = key.thumbprint(hash_alg=hash_alg)
        else:
            candidate = jwk_thumbprint(key, hash_alg=hash_alg)
        if candidate == thumbprint:
            return key

    raise JWKError("Unable to find a key matching the given thumbprint")
