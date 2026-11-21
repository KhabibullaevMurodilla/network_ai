"""Verifies user tokens signed asymmetrically (new Supabase projects) as
well as legacy HS256. Uses a locally generated EC key and a stub JWKS
client -- NOT a real Supabase project."""
import time, jwt, pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from app.core import auth
from app.core.config import settings


class _Key:
    def __init__(self, k): self.key = k

class _StubJWKS:
    def __init__(self, pub): self.pub = pub
    def get_signing_key_from_jwt(self, t): return _Key(self.pub)


def _claims(**kw):
    return {"sub": "u1", "aud": "authenticated", "exp": int(time.time()) + 300, **kw}


@pytest.fixture
def ec_pair(monkeypatch):
    priv = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(auth, "_jwks_client", _StubJWKS(priv.public_key()))
    return priv


def test_es256_token_accepted(ec_pair):
    t = jwt.encode(_claims(), ec_pair, algorithm="ES256", headers={"kid": "k"})
    assert auth._decode_supabase_jwt(t)["sub"] == "u1"


def test_es256_signed_by_other_key_rejected(ec_pair):
    other = ec.generate_private_key(ec.SECP256R1())
    t = jwt.encode(_claims(), other, algorithm="ES256")
    with pytest.raises(jwt.PyJWTError):
        auth._decode_supabase_jwt(t)


def test_hs256_still_works():
    t = jwt.encode(_claims(), settings.SUPABASE_JWT_SECRET, algorithm="HS256")
    assert auth._decode_supabase_jwt(t)["sub"] == "u1"


def test_hs256_wrong_secret_rejected():
    t = jwt.encode(_claims(), "x" * 40, algorithm="HS256")
    with pytest.raises(jwt.PyJWTError):
        auth._decode_supabase_jwt(t)


def test_alg_none_rejected():
    t = jwt.encode(_claims(), None, algorithm="none")
    with pytest.raises(jwt.PyJWTError):
        auth._decode_supabase_jwt(t)


def test_wrong_audience_rejected(ec_pair):
    t = jwt.encode(_claims(aud="other"), ec_pair, algorithm="ES256")
    with pytest.raises(jwt.PyJWTError):
        auth._decode_supabase_jwt(t)


def test_expired_rejected(ec_pair):
    t = jwt.encode(_claims(exp=int(time.time()) - 10), ec_pair, algorithm="ES256")
    with pytest.raises(jwt.PyJWTError):
        auth._decode_supabase_jwt(t)
