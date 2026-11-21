"""Team management (v6.4) -- invite teammates, list a tenant's members,
change a teammate's role/focus, remove one. This is the missing
prerequisite for admin-assigned "focus": before this router existed there
was no way for a second person to join a tenant at all (no signup page, no
profiles row ever created for anyone but whoever set up the tenant), so
"an admin assigns focus to a teammate" had nowhere to act. See core/team.py
for the actual Supabase Auth invite call and why it isn't a DB trigger.

`focus` (security/network/ot/executive) is deliberately a separate axis
from `role` (viewer/analyst/admin/owner, see core/auth.py's ROLE_RANK):
role is enforced server-side on every write; focus only ever changes what
the dashboard chooses to show first -- it is never treated as a permission
check anywhere in this codebase, and never will be, so a UI bug in a
focus-aware page can't become a privilege-escalation bug."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..core.auth import require_user, require_admin, ROLE_RANK
from ..core.db import get_db
from ..core.audit import log_action
from ..core.team import invite_user, InviteError
from ..core.limiter import limiter, user_key_func

router = APIRouter(tags=["team"])

VALID_FOCUS = ("security", "network", "ot", "executive")
MEMBER_FIELDS = "id, email, role, focus, invited_by, invited_at, created_at"


def _validate_focus(focus: str | None):
    if focus is not None and focus not in VALID_FOCUS:
        raise HTTPException(status_code=400, detail=f"focus must be one of {VALID_FOCUS} or null")


class InviteRequest(BaseModel):
    email: str
    role: str = "viewer"
    focus: str | None = None


@router.post("/team/invite")
@limiter.limit("20/minute", key_func=user_key_func)
async def invite_teammate(request: Request, req: InviteRequest, user=Depends(require_admin)):
    if req.role not in ROLE_RANK:
        raise HTTPException(status_code=400, detail=f"role must be one of {tuple(ROLE_RANK)}")
    _validate_focus(req.focus)
    if ROLE_RANK[req.role] > ROLE_RANK[user["role"]]:
        raise HTTPException(status_code=403, detail="You cannot invite someone to a role higher than your own")

    db = get_db()
    existing = (
        db.table("profiles").select("id").eq("tenant_id", user["tenant_id"]).eq("email", req.email).limit(1).execute()
    ).data
    if existing:
        raise HTTPException(status_code=409, detail="This email is already a member of your team")

    try:
        new_user_id = invite_user(req.email)
    except InviteError as e:
        raise HTTPException(status_code=409, detail=str(e))

    row = db.table("profiles").insert({
        "id": new_user_id, "tenant_id": user["tenant_id"], "role": req.role, "focus": req.focus,
        "email": req.email, "invited_by": user["user_id"],
        "invited_at": datetime.now(timezone.utc).isoformat(),
    }).execute()
    log_action(user["tenant_id"], actor=user["user_id"], action="team.invited",
               detail={"email": req.email, "role": req.role, "focus": req.focus, "invited_user_id": new_user_id})
    return row.data[0]


@router.get("/team")
async def list_team(user=Depends(require_user)):
    db = get_db()
    res = (
        db.table("profiles").select(MEMBER_FIELDS)
        .eq("tenant_id", user["tenant_id"]).order("created_at", desc=False).execute()
    )
    return res.data


class UpdateMemberRequest(BaseModel):
    role: str | None = None
    focus: str | None = "__unset__"  # sentinel: distinguishes "don't touch focus" from "clear focus to null"


@router.patch("/team/{member_id}")
@limiter.limit("20/minute", key_func=user_key_func)
async def update_teammate(request: Request, member_id: str, req: UpdateMemberRequest, user=Depends(require_admin)):
    if member_id == user["user_id"]:
        raise HTTPException(
            status_code=400,
            detail="Use PATCH /team/me/focus to change your own focus; ask another admin/owner to change your role",
        )
    db = get_db()
    target = (
        db.table("profiles").select("id, role, tenant_id").eq("id", member_id).eq("tenant_id", user["tenant_id"]).limit(1).execute()
    ).data
    if not target:
        raise HTTPException(status_code=404, detail="No such teammate")
    target = target[0]
    if ROLE_RANK.get(target["role"], 0) > ROLE_RANK[user["role"]]:
        raise HTTPException(status_code=403, detail="You cannot modify a teammate with a higher role than your own")

    update: dict = {}
    if req.role is not None:
        if req.role not in ROLE_RANK:
            raise HTTPException(status_code=400, detail=f"role must be one of {tuple(ROLE_RANK)}")
        if ROLE_RANK[req.role] > ROLE_RANK[user["role"]]:
            raise HTTPException(status_code=403, detail="You cannot grant a role higher than your own")
        if target["role"] == "owner" and req.role != "owner":
            owners = (
                db.table("profiles").select("id").eq("tenant_id", user["tenant_id"]).eq("role", "owner").execute()
            ).data
            if len(owners) <= 1:
                raise HTTPException(status_code=400, detail="Cannot demote the only owner -- promote someone else first")
        update["role"] = req.role
    if req.focus != "__unset__":
        _validate_focus(req.focus)
        update["focus"] = req.focus

    if not update:
        raise HTTPException(status_code=400, detail="Nothing to update")

    db.table("profiles").update(update).eq("id", member_id).execute()
    log_action(user["tenant_id"], actor=user["user_id"], action="team.updated", detail={"member_id": member_id, **update})
    return {"updated": True, **update}


@router.delete("/team/{member_id}")
async def remove_teammate(member_id: str, user=Depends(require_admin)):
    if member_id == user["user_id"]:
        raise HTTPException(status_code=400, detail="You cannot remove yourself from the team")
    db = get_db()
    target = (
        db.table("profiles").select("id, role").eq("id", member_id).eq("tenant_id", user["tenant_id"]).limit(1).execute()
    ).data
    if not target:
        raise HTTPException(status_code=404, detail="No such teammate")
    if ROLE_RANK.get(target[0]["role"], 0) > ROLE_RANK[user["role"]]:
        raise HTTPException(status_code=403, detail="You cannot remove a teammate with a higher role than your own")
    if target[0]["role"] == "owner":
        owners = (
            db.table("profiles").select("id").eq("tenant_id", user["tenant_id"]).eq("role", "owner").execute()
        ).data
        if len(owners) <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove the only owner")
    # Deletes the profile only -- the underlying Supabase Auth user is left
    # in place (same non-destructive posture as api_keys.revoked_at: this
    # removes *access*, not the account). Without a profiles row,
    # require_user's lookup (core/auth.py) 403s them on their very next
    # request -- same effect as a real deletion, without needing the auth
    # admin API on the delete path too.
    db.table("profiles").delete().eq("id", member_id).execute()
    log_action(user["tenant_id"], actor=user["user_id"], action="team.removed", detail={"member_id": member_id})
    return {"removed": True}


class SelfFocusRequest(BaseModel):
    focus: str | None


@router.patch("/team/me/focus")
async def update_my_focus(req: SelfFocusRequest, user=Depends(require_user)):
    _validate_focus(req.focus)
    db = get_db()
    db.table("profiles").update({"focus": req.focus}).eq("id", user["user_id"]).execute()
    log_action(user["tenant_id"], actor=user["user_id"], action="profile.focus_updated", detail={"focus": req.focus})
    return {"focus": req.focus}
