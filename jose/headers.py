"""
JOSE Header merging and validation.

A JOSE Header (RFC 7515 Section 4 for JWS, RFC 7516 Section 4 for JWE) is the
union of up to three JSON objects, merged in this order:

1. the JWE/JWS Protected Header (integrity protected),
2. the JWE Shared Unprotected Header (JWE JSON Serialization only),
3. the JWE Per-Recipient Unprotected Header (JWE JSON Serialization only).

The same Header Parameter name MUST NOT occur in more than one of these
objects, and parameters declared critical via the "crit" Header Parameter MUST
live in the Protected Header and MUST be understood by the implementation.
All merge entry points therefore pass through the single gate implemented in
this module instead of blindly dict-updating the headers together.
"""

from collections.abc import Mapping

from .exceptions import JOSEError

#: Names of the header locations, used in error messages so that a failure can
#: be traced back to the exact header that triggered it.
PROTECTED_HEADER = "protected header"
SHARED_UNPROTECTED_HEADER = "shared unprotected header"
RECIPIENT_UNPROTECTED_HEADER = "per-recipient unprotected header"

#: Registered JOSE Header Parameters (RFC 7515 Section 4.1, RFC 7516
#: Section 4.1 and RFC 7517). Only names present in this registry are
#: considered understood when referenced by the "crit" Header Parameter.
REGISTERED_HEADER_PARAMETERS = frozenset(
    {
        "alg",
        "jku",
        "jwk",
        "kid",
        "x5u",
        "x5c",
        "x5t",
        "x5t#S256",
        "typ",
        "cty",
        "crit",
        "enc",
        "zip",
        "epk",
        "apu",
        "apv",
        "iv",
        "tag",
        "p2s",
        "p2c",
    }
)


def merge_headers(protected=None, shared_unprotected=None, recipient_unprotected=None):
    """Merge the three JOSE Header sources into a single validated header.

    Args:
        protected (Mapping): The integrity-protected JOSE Header.
        shared_unprotected (Mapping): The shared unprotected header, if any.
        recipient_unprotected (Mapping): The per-recipient unprotected header,
            if any.

    Returns:
        dict: The merged JOSE Header.

    Raises:
        JOSEError: If a header source is not a JSON object, the same parameter
            name occurs in more than one source, or a "crit" parameter is not
            present in the protected header or is not understood.
    """
    sources = (
        (PROTECTED_HEADER, protected),
        (SHARED_UNPROTECTED_HEADER, shared_unprotected),
        (RECIPIENT_UNPROTECTED_HEADER, recipient_unprotected),
    )

    merged = {}
    seen = {}
    for location, header in sources:
        if header is None:
            continue
        if not isinstance(header, Mapping):
            raise JOSEError(f"The {location} must be a JSON object")
        for name in header:
            if name in seen:
                raise JOSEError(
                    f"Header parameter '{name}' occurs in both the {seen[name]} "
                    f"and the {location}; duplicate JOSE Header Parameter names "
                    "are not allowed"
                )
            seen[name] = location
            merged[name] = header[name]

    _validate_crit(protected or {}, shared_unprotected or {}, recipient_unprotected or {})
    return merged


def _validate_crit(protected, shared_unprotected, recipient_unprotected):
    """Validate the "crit" (critical) Header Parameter per RFC 7515 4.1.11."""
    if "crit" in shared_unprotected or "crit" in recipient_unprotected:
        raise JOSEError('The "crit" Header Parameter MUST be carried in the JOSE Protected Header')

    crit = protected.get("crit")
    if crit is None:
        # Messages without any critical extensions keep parsing exactly as
        # before; the check only hard-fails once "crit" is actually declared.
        return

    if not isinstance(crit, list) or not crit or any(not isinstance(name, str) for name in crit):
        raise JOSEError('The "crit" Header Parameter must be a non-empty list of strings')

    if len(set(crit)) != len(crit):
        raise JOSEError('The "crit" Header Parameter must not list duplicate names')

    for name in crit:
        if name not in protected:
            raise JOSEError(f"Critical header parameter '{name}' MUST be present in the JOSE " "Protected Header")
        if name not in REGISTERED_HEADER_PARAMETERS:
            raise JOSEError(
                f"Critical header parameter '{name}' is not a registered, understood " "JOSE Header Parameter"
            )


def reject_duplicate_json_members(pairs):
    """``object_pairs_hook`` rejecting duplicate member names in one object.

    JSON parsers silently keep the last value when an object repeats a member
    name. The JOSE specs forbid duplicate Header Parameter names even inside a
    single header object, so feed this hook to ``json.loads`` when decoding a
    JOSE header.
    """
    names = [name for name, _ in pairs]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise JOSEError("Duplicate JOSE Header Parameter name(s) within a single header: " + ", ".join(duplicates))
    return dict(pairs)
