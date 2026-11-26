import json

try:
    from collections.abc import Iterable, Mapping
except ImportError:
    from collections import Iterable, Mapping

from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.exceptions import JWKError
from jose.utils import base64url_decode

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

    kid = None
    if isinstance(key_data, Mapping):
        kid = key_data.get("kid")

        # The AES and direct backends operate on raw key material.  Accept an
        # oct JWK (as found in a JWK set) in the same way HMACKey does.
        if key_data.get("kty") == "oct" and (algorithm in ALGORITHMS.AES or algorithm == ALGORITHMS.DIR):
            encoded_key = key_data.get("k")
            if encoded_key is None:
                raise JWKError("Missing required JWK member 'k'")
            if isinstance(encoded_key, str):
                encoded_key = encoded_key.encode("ascii")
            key_data = base64url_decode(encoded_key)

    key = key_class(key_data, algorithm)

    # Keep the server-assigned key identifier available for callers that need
    # to select a key from a set and write it into a token header.
    if kid is not None:
        key.kid = kid

    return key


def get_key_id(key):
    """Return the ``kid`` associated with a key, if it has one.

    Args:
        key: A JWK mapping, a :class:`jose.backends.base.Key` instance, or a
            raw key value.

    Returns:
        The key identifier, or ``None`` when the key does not carry one.
    """
    if isinstance(key, Key):
        kid = getattr(key, "kid", None)
        if kid is not None:
            return kid
        try:
            return key.to_dict().get("kid")
        except Exception:
            return None

    if isinstance(key, Mapping):
        return key.get("kid")

    return None


def _get_keys(key, kid=None):
    """Normalize a key argument into the keys it contains.

    The accepted shapes match the signing APIs: an individual JWK or
    :class:`jose.backends.base.Key`, a JWK set (mapping or JSON string), a
    mapping of ``kid`` to key, or any iterable of those values.  When ``kid``
    is provided, only keys carrying that identifier are returned.
    """
    if isinstance(key, Key):
        if kid is not None and get_key_id(key) != kid:
            return []
        return (key,)

    try:
        key = json.loads(key, parse_int=str, parse_float=str)
    except Exception:
        pass

    if isinstance(key, Mapping):
        if "keys" in key:
            # JWK Set per RFC 7517
            keys = key["keys"]
            if kid is not None:
                return [candidate for candidate in keys if get_key_id(candidate) == kid]
            return keys
        elif "kty" in key:
            # Individual JWK per RFC 7517
            if kid is not None and get_key_id(key) != kid:
                return []
            return (key,)
        else:
            # Some other mapping. Firebase uses just dict of kid, cert pairs
            if kid is not None and kid in key:
                return [key[kid]]

            values = key.values()
            if values:
                if kid is not None:
                    return [candidate for candidate in values if get_key_id(candidate) == kid]
                return values
            return (key,)

    # Iterable but not text or mapping => list- or tuple-like
    elif isinstance(key, Iterable) and not (isinstance(key, str) or isinstance(key, bytes)):
        if kid is not None:
            return [candidate for candidate in key if get_key_id(candidate) == kid]
        return key

    # Scalar value, wrap in tuple.
    else:
        if kid is not None and get_key_id(key) != kid:
            return []
        return (key,)


# Public alias for callers that need the same normalization rules as JWS.
get_keys = _get_keys


def get_keys_by_kid(keys, kid):
    """Return all keys in ``keys`` carrying the given ``kid``."""
    if kid is None:
        return list(_get_keys(keys))
    return list(_get_keys(keys, kid))


def get_key_candidates(keys, kid):
    """Return the decryption candidates for a header ``kid``.

    Keys matching the identifier are preferred.  If the set contains no
    matching identifier (for example for a token created before the header
    carried one), all keys are returned so callers can still try them.
    """
    all_keys = list(_get_keys(keys))
    if kid is None:
        return all_keys

    matching = [candidate for candidate in all_keys if get_key_id(candidate) == kid]
    return matching or all_keys


def get_key_by_kid(keys, kid):
    """Return the first key in ``keys`` carrying the given ``kid``.

    Raises:
        JWKError: If no key matches.
    """
    matching = get_keys_by_kid(keys, kid)
    if not matching:
        raise JWKError("Unable to find a key matching the given kid")
    return matching[0]
