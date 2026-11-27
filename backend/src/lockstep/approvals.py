"""Four-eyes approvals, for every kind of plan Lockstep applies: sync plans, access plans
(policies, roles, groups, tuning, engine objects) and undo plans.

An approval says that someone other than the plan's creator checked it against the Vaults and
approved it. It's signed on its own, over the plan's ID and signature, so it can't change what the
plan does, and it travels between installations like the plan (lockstep.plansign).

Approvals are compared by Vault **entity**, per Vault the plan writes: the approver's entity must
differ from the creator's on each one, and from every other approval's (one person, one approval).
A root or orphan token has no entity and can't approve.

How many a plan needs: LOCKSTEP_PLAN_APPROVALS for every plan applied on the installation, or a
preset's `approvals` for plans writing to that Vault (writepolicy.approvals_for). Who may approve:
anyone, or, with LOCKSTEP_PLAN_APPROVER_POLICIES or a preset's `approver_policies`, only someone
whose token holds one of those Vault policies (directly or through an identity group). The
approver's policies are recorded in the signed approval, so an installation the plan travels to
checks the same thing.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel

from . import plansign
from .config import Settings
from .plansign import Issuer
from .session import Connection

audit = logging.getLogger("lockstep.audit")

Kind = Literal["sync", "access", "undo"]
WHERE = {"sync": "Sync plans", "access": "Policies (Open an access plan…)", "undo": "Sync plans"}


class Approval(BaseModel):
    """Someone other than the creator checked the plan and approved it. Signed separately, so an
    approval never changes what the plan does."""
    by: str  # display name
    entities: dict[str, str]  # Vault (a key per Vault the plan writes) -> the approver's entity ID there
    # Vault -> the approver's policies there when they approved (token and identity policies).
    # Older approvals have none: they don't count where approver policies are required.
    policies: dict[str, list[str]] = {}
    at: str
    issuer: Issuer | None = None  # the installation that signed the approval
    signature: str = ""


class ApprovalsOut(BaseModel):
    required: int  # how many this installation asks for, for the Vaults the plan writes
    approved_by: list[str]  # the approvals that count, one per person
    approver_policies: list[str] = []  # an approver must hold one of these (empty: anyone but the creator)
    problems: list[str] = []  # approvals that don't count, and why


def _key(settings: Settings) -> bytes:
    return hashlib.sha256(b"lockstep-plan-approval-v1\0" + settings.session_key.encode()).digest()


def _message(kind: Kind, plan_id: str, plan_signature: str, a: Approval) -> bytes:
    body = {"plan": plan_id, "plan_signature": plan_signature, "by": a.by, "entities": a.entities, "at": a.at,
            "issuer": a.issuer.model_dump() if a.issuer else None}
    if kind != "sync":  # sync approvals were signed before there were other kinds
        body["kind"] = kind
    if a.policies:  # nor did approvals record policies
        body["policies"] = a.policies
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _short(policies: list[str]) -> str:
    return ", ".join(policies) if len(policies) <= 3 else f"{', '.join(policies[:3])} or {len(policies) - 3} more"


def count(kind: Kind, plan_id: str, plan_signature: str, approvals: list[Approval], creators: dict[str, str],
          labels: dict[str, str], required: int, settings: Settings,
          approver_policies: dict[str, list[str]] | None = None) -> ApprovalsOut:
    """Which approvals count: signed by a trusted installation, for this plan, by someone whose
    entity differs from the creator's on every Vault in `creators` (key -> creator's entity ID),
    holding one of `approver_policies` (key -> policies; empty: no requirement) on each Vault, and
    not by someone whose approval already counts."""
    need = {k: v for k, v in (approver_policies or {}).items() if v}
    ok: list[str] = []
    seen: set[str] = set()  # the entity IDs of approvals that count
    problems: list[str] = []
    for a in approvals:
        try:
            plansign.verify(_message(kind, plan_id, plan_signature, a), a.signature, a.issuer, settings, _key(settings))
        except HTTPException:
            problems.append(f"The approval by {a.by} isn't valid here (edited, or signed by a server this one doesn't trust).")
            continue
        same = [k for k in creators if not a.entities.get(k) or a.entities.get(k) == creators[k]]
        if same:
            problems.append(f"The approval by {a.by} doesn't count: they made the plan, or had no Vault identity, on "
                            f"{', '.join(labels.get(k, k) for k in same)}.")
            continue
        lacking = [k for k in need if k in creators and not set(a.policies.get(k, [])) & set(need[k])]
        if lacking:
            problems.append(f"The approval by {a.by} doesn't count: approving needs one of the policies {_short(need[lacking[0]])} "
                            f"on {', '.join(labels.get(k, k) for k in lacking)}, and they didn't hold one when they approved.")
            continue
        ids = {a.entities[k] for k in creators}
        if ids & seen:
            continue  # the same person approved again: it counts once
        seen |= ids
        ok.append(a.by)
    return ApprovalsOut(required=required, approved_by=ok, problems=problems,
                        approver_policies=sorted({p for v in need.values() for p in v}))


def approve(kind: Kind, plan_id: str, plan_signature: str, approvers: dict[str, Connection], creators: dict[str, str],
            labels: dict[str, str], settings: Settings, approver_policies: dict[str, list[str]] | None = None,
            existing: list[Approval] | None = None) -> Approval:
    """A new approval from whoever is signed in to each Vault the plan writes (key -> connection).
    Refuses a sign-in without an entity, the plan's creator, someone without one of the approver
    policies, and someone who has approved it already. Audit-logged."""
    need = approver_policies or {}
    for k, conn in approvers.items():
        if not conn.entity_id:
            raise HTTPException(400, detail={"message": (
                f"Approving needs a Vault identity (an entity) on {labels.get(k, k)}: sign in as a person "
                "(userpass, LDAP, OIDC…), not with a root or orphan token.")})
        if conn.entity_id == creators.get(k):
            raise HTTPException(409, detail={"message": "You made this plan: someone else has to approve it."})
        if need.get(k) and not set(conn.policies) & set(need[k]):
            raise HTTPException(403, detail={"message": (
                f"Approving plans here needs one of the Vault policies {_short(need[k])} on {labels.get(k, k)}, "
                "and this sign-in doesn't have one. Ask a Vault admin, or have someone who has one approve it.")})
        if any(a.entities.get(k) == conn.entity_id for a in existing or []):
            raise HTTPException(409, detail={"message": "You've approved this plan already: the next approval has to come from someone else."})
    first = next(iter(approvers.values()))
    keys = plansign.keys(settings)
    a = Approval(by=first.display_name or first.auth_method, entities={k: c.entity_id for k, c in approvers.items()},
                 policies={k: sorted(c.policies) for k, c in approvers.items()} if any(need.values()) else {},
                 at=plansign.now_iso(), issuer=Issuer(name=keys.name, key_id=keys.own_id))
    a.signature = plansign.sign(_message(kind, plan_id, plan_signature, a), settings, _key(settings))
    audit.info(json.dumps({"ts": a.at, "event": "plan.approve", "outcome": "approved", "kind": kind, "plan_id": plan_id,
                           "actor": {"identity": a.by, "entities": a.entities,
                                     "accessors": {k: c.accessor for k, c in approvers.items()}}}, sort_keys=True))
    return a


def require(kind: Kind, out: ApprovalsOut) -> None:
    """Refuse to apply (409) until the plan has the approvals this installation asks for."""
    if len(out.approved_by) < out.required:
        who = "an approval from someone other than its creator" if out.required == 1 \
            else f"{out.required} approvals from different people other than its creator ({len(out.approved_by)} so far)"
        if out.approver_policies:
            who += f", holding one of the Vault policies {_short(out.approver_policies)}"
        raise HTTPException(409, detail={"message": (
            f"This plan needs {who} before it's applied here: they open it in "
            f"{WHERE[kind]}, check it and choose Approve." + (" " + " ".join(out.problems) if out.problems else "")),
            "approvals": out.model_dump()})
