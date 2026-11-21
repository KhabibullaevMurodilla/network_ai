"""v6.4 team management. invite_user() (the real Supabase Auth call) is
patched -- this sandbox never sends a real invite email; everything else
(role-rank guardrails, tenant scoping, last-owner protection, audit log)
runs for real against FakeDB."""
from unittest.mock import patch

import jwt
import pytest
from fastapi.testclient import TestClient

from app.core.team import InviteError
from app.main import app
from tests.fake_db import FakeDB

SECRET = "test-jwt-secret-not-real"
T1, T2 = "a1000000-0000-0000-0000-000000000001", "a2000000-0000-0000-0000-000000000002"
OWNER, ADMIN, ANALYST, OTHER_T = "b1000000-0000-0000-0000-000000000001", "b1000000-0000-0000-0000-000000000002", "b1000000-0000-0000-0000-000000000003", "b2000000-0000-0000-0000-000000000009"


def auth(uid):
    t = jwt.encode({"sub": uid, "aud": "authenticated", "exp": 9999999999}, SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {t}"}


@pytest.fixture
def db():
    f = FakeDB()
    f.seed("profiles", [
        {"id": OWNER, "tenant_id": T1, "role": "owner", "email": "o@x.com", "focus": None},
        {"id": ADMIN, "tenant_id": T1, "role": "admin", "email": "a@x.com", "focus": "security"},
        {"id": ANALYST, "tenant_id": T1, "role": "analyst", "email": "an@x.com", "focus": None},
        {"id": OTHER_T, "tenant_id": T2, "role": "owner", "email": "z@y.com", "focus": None},
    ])
    ps = [patch(t, return_value=f) for t in ("app.core.auth.get_db", "app.routers.team.get_db", "app.core.audit.get_db")]
    [p.start() for p in ps]
    yield f
    [p.stop() for p in ps]


@pytest.fixture
def client(db):
    from app.core.limiter import limiter
    limiter.reset()
    return TestClient(app)


def test_invite_creates_profile_and_audits(client, db):
    with patch("app.routers.team.invite_user", return_value="c0000000-0000-0000-0000-000000000001") as inv:
        r = client.post("/team/invite", headers=auth(ADMIN), json={"email": "new@x.com", "role": "analyst", "focus": "ot"})
    assert r.status_code == 200
    inv.assert_called_once_with("new@x.com")
    row = db.table("profiles").select("*").eq("email", "new@x.com").execute().data[0]
    assert (row["tenant_id"], row["role"], row["focus"], row["invited_by"]) == (T1, "analyst", "ot", ADMIN)
    assert db.table("audit_log").select("*").eq("action", "team.invited").execute().data


def test_analyst_cannot_invite(client):
    assert client.post("/team/invite", headers=auth(ANALYST), json={"email": "n@x.com"}).status_code == 403


def test_admin_cannot_invite_owner(client):
    with patch("app.routers.team.invite_user", return_value="x"):
        assert client.post("/team/invite", headers=auth(ADMIN), json={"email": "n@x.com", "role": "owner"}).status_code == 403


def test_duplicate_email_in_tenant_409(client):
    assert client.post("/team/invite", headers=auth(ADMIN), json={"email": "an@x.com"}).status_code == 409


def test_supabase_invite_failure_is_clean_409(client, db):
    with patch("app.routers.team.invite_user", side_effect=InviteError("already registered")):
        r = client.post("/team/invite", headers=auth(ADMIN), json={"email": "n@x.com"})
    assert r.status_code == 409
    assert not db.table("profiles").select("id").eq("email", "n@x.com").execute().data  # no half-created profile


def test_invalid_focus_and_role_rejected(client):
    assert client.post("/team/invite", headers=auth(ADMIN), json={"email": "n@x.com", "focus": "hacker"}).status_code == 400
    assert client.post("/team/invite", headers=auth(ADMIN), json={"email": "n@x.com", "role": "god"}).status_code == 400


def test_list_is_tenant_scoped(client):
    emails = {m["email"] for m in client.get("/team", headers=auth(ANALYST)).json()}
    assert emails == {"o@x.com", "a@x.com", "an@x.com"}  # never z@y.com


def test_admin_assigns_focus_and_role(client, db):
    r = client.patch(f"/team/{ANALYST}", headers=auth(ADMIN), json={"focus": "network", "role": "admin"})
    assert r.status_code == 200
    row = db.table("profiles").select("*").eq("id", ANALYST).execute().data[0]
    assert (row["focus"], row["role"]) == ("network", "admin")


def test_focus_can_be_cleared_to_null(client, db):
    client.patch(f"/team/{ADMIN}", headers=auth(OWNER), json={"focus": None})
    assert db.table("profiles").select("*").eq("id", ADMIN).execute().data[0]["focus"] is None


def test_cannot_grant_above_own_rank(client):
    assert client.patch(f"/team/{ANALYST}", headers=auth(ADMIN), json={"role": "owner"}).status_code == 403


def test_cannot_edit_self_via_team_patch(client):
    assert client.patch(f"/team/{ADMIN}", headers=auth(ADMIN), json={"role": "viewer"}).status_code == 400


def test_cannot_touch_other_tenants_member(client):
    assert client.patch(f"/team/{OTHER_T}", headers=auth(OWNER), json={"focus": "ot"}).status_code == 404
    assert client.delete(f"/team/{OTHER_T}", headers=auth(OWNER)).status_code == 404


def test_admin_cannot_demote_or_remove_an_owner(client, db):
    """Real hole found by writing this suite: nothing originally checked
    the TARGET's rank, so an admin could demote or remove an owner."""
    assert client.patch(f"/team/{OWNER}", headers=auth(ADMIN), json={"role": "viewer"}).status_code == 403
    assert client.delete(f"/team/{OWNER}", headers=auth(ADMIN)).status_code == 403
    assert db.table("profiles").select("role").eq("id", OWNER).execute().data[0]["role"] == "owner"


def test_owner_can_demote_a_co_owner_but_never_the_last_one(client, db):
    CO = "b1000000-0000-0000-0000-0000000000ff"
    db.seed("profiles", [{"id": CO, "tenant_id": T1, "role": "owner", "email": "o2@x.com"}])
    assert client.patch(f"/team/{CO}", headers=auth(OWNER), json={"role": "admin"}).status_code == 200  # 2 owners -> ok
    # now OWNER is the only owner; CO (admin) can't touch them (rank), and
    # the last-owner guard is the second line of defence if rank ever changes:
    assert client.patch(f"/team/{OWNER}", headers=auth(CO), json={"role": "viewer"}).status_code == 403
    assert client.delete(f"/team/{OWNER}", headers=auth(CO)).status_code == 403


def test_remove_deletes_profile_and_locks_them_out(client, db):
    assert client.delete(f"/team/{ANALYST}", headers=auth(ADMIN)).status_code == 200
    assert client.get("/team", headers=auth(ANALYST)).status_code == 403  # no profile -> no access


def test_cannot_remove_self(client):
    assert client.delete(f"/team/{ADMIN}", headers=auth(ADMIN)).status_code == 400


def test_self_serve_focus(client, db):
    r = client.patch("/team/me/focus", headers=auth(ANALYST), json={"focus": "ot"})
    assert r.status_code == 200
    assert db.table("profiles").select("*").eq("id", ANALYST).execute().data[0]["focus"] == "ot"
    assert client.patch("/team/me/focus", headers=auth(ANALYST), json={"focus": "bogus"}).status_code == 400


def test_focus_grants_no_privileges(client, db):
    """focus is display-only: an executive-focus owner is still an owner,
    and a security-focus viewer is still a viewer."""
    db.seed("profiles", [{"id": "b3000000-0000-0000-0000-000000000001", "tenant_id": T1, "role": "viewer", "email": "v@x.com", "focus": "security"}])
    assert client.post("/team/invite", headers=auth("b3000000-0000-0000-0000-000000000001"), json={"email": "n@x.com"}).status_code == 403
