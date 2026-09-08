# JWT verification: `InvalidKeyError` bypasses the audit log

**Status:** fixed here, not yet applied to sibling services.

## The gap

`voms-token-service`, `krb5-token-service`, and `condor-token-service` all
verify their inbound AF Broker Identity Token with the same `identity.py`
shape:

```python
try:
    ...
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
    return jwt.decode(token, public_key, ...)
except jwt.InvalidTokenError as exc:
    error = exc
except (ValueError, KeyError) as exc:
    error = exc
```

`jwt.algorithms.RSAAlgorithm.from_jwk` can raise
`jwt.exceptions.InvalidKeyError` for a malformed or non-RSA JWKS entry (e.g.
a stray EC key with no matching `kid`, hit via the single-key fallback in
`_select_jwk`). `InvalidKeyError` is a `PyJWTError` subclass, but **not** an
`InvalidTokenError` subclass, and it isn't `ValueError`/`KeyError` either:

```
>>> [c.__name__ for c in jwt.exceptions.InvalidKeyError.__mro__]
['InvalidKeyError', 'PyJWTError', 'Exception', 'BaseException', 'object']
```

So it escapes both `except` clauses above, propagates out of
`verify_broker_token` uncaught, and (since it isn't an `HTTPException`
either) surfaces in the FastAPI app as a bare unhandled 500 — **with no
audit log line at all**, since the route handler's own `except
HTTPException` never catches it. A broker JWKS key-rotation glitch or
misconfiguration (a non-RSA key appearing in the published JWKS) would
silently produce unaudited 500s instead of the usual audited 401.

Found during code review of `servicex-token-service`'s `app.py` (Task 6),
2026-09-09. Confirmed the identical structure — and therefore the identical
gap — exists unchanged in `condor-token-service`'s `identity.py`.

## The fix (applied in this repo only)

Widen the first `except` clause from `jwt.InvalidTokenError` to
`jwt.PyJWTError` (the common base for both `InvalidTokenError` and
`InvalidKeyError`), so any PyJWT-raised error during verification is
classified as a normal, audited 401 rather than an unhandled 500:

```python
except jwt.PyJWTError as exc:
    error = exc
except (ValueError, KeyError) as exc:
    error = exc
```

See `src/servicex_token_service/identity.py`.

## Follow-up needed

Giordon asked for this to be fixed here first as a reference, then applied
to the sibling services separately (file an issue against each, or port the
same one-line change): `voms-token-service`, `krb5-token-service`,
`condor-token-service`. Not done as part of this change — those repos were
treated as read-only references throughout `servicex-token-service`'s
build and were not modified.
