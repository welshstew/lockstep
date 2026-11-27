"""The environment matrix: one baseline compared with several environments at once."""

from __future__ import annotations

from contextlib import AsyncExitStack
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import driftsign, matrix, plansign
from ..cli.drift import Baseline
from ..config import Settings, get_settings
from ..rules import Rules
from ..session import SessionData, load_session
from ..vault import VaultError
from .compare import AnySide, FileSide, side_client, side_connection
from .connections import vault_http_error

router = APIRouter(prefix="/api", tags=["compare"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

Name = Field(min_length=1, max_length=60)


class MatrixEnvironment(BaseModel):
    name: str = Name
    side: AnySide
    rules: Rules | None = None  # this pair's comparison profile
    # Accepted drift for this pair: a drift baseline (lockstep baseline update, the drift check's
    # base.json). What it lists, with the same status, is shown but isn't counted as odd.
    accepted: Baseline | None = None
    accepted_name: str = Field(default="accepted drift", max_length=200)


class MatrixRequest(BaseModel):
    baseline_name: str = Field(default="baseline", min_length=1, max_length=60)
    baseline: AnySide  # a Vault location, or an export file
    environments: list[MatrixEnvironment] = Field(min_length=1, max_length=matrix.MAX_ENVIRONMENTS)
    include_equal: bool = False


@router.post("/matrix", response_model=matrix.Matrix)
async def compare_matrix(body: MatrixRequest, session: Sess, settings: Conf):
    """Compare the baseline with each environment, each pair under its own profile, and return the
    grid with the odd one out first. Statuses only, never values."""
    names = [body.baseline_name.strip(), *(e.name.strip() for e in body.environments)]
    if len(set(names)) != len(names):
        raise HTTPException(400, detail={"message": "Give the baseline and each environment a different name."})
    bmount, bprefix = body.baseline.norm()
    signers = {}
    for i, e in enumerate(body.environments):
        if e.accepted is not None:
            _check_accepted(e, body.baseline, bmount, bprefix)
            signers[i] = _signer(e, settings)
    bconn = side_connection(body.baseline, session)
    conns = [side_connection(e.side, session) for e in body.environments]
    async with AsyncExitStack() as stack:
        base = await stack.enter_async_context(side_client(body.baseline, bconn, settings))
        envs = []
        for i, (e, conn) in enumerate(zip(body.environments, conns)):
            mount, prefix = e.side.norm()
            client = await stack.enter_async_context(side_client(e.side, conn, settings))
            accepted = {(f.path, f.key): f.status for f in e.accepted.drift} if e.accepted is not None else None
            envs.append(matrix.EnvInput(name=e.name.strip(), client=client, mount=mount, prefix=prefix, rules=e.rules,
                                        accepted=accepted, accepted_name=e.accepted_name, accepted_signer=signers.get(i)))
        try:
            return await matrix.run(names[0], base, bmount, bprefix, envs, max_secrets=settings.max_tree_secrets,
                                    include_equal=body.include_equal,
                                    base_kind="file" if isinstance(body.baseline, FileSide) else "vault")
        except VaultError as e:
            raise vault_http_error(e) from e


def _signer(e: MatrixEnvironment, settings) -> str | None:
    """Check a signed accepted-drift file against this server's trusted plan keys: an edited one, or one
    signed by a key it doesn't trust, is refused. Returns who signed it (None: unsigned, or no keys to check)."""
    b = e.accepted
    keys = plansign.keys(settings)
    try:
        note = driftsign.check("baseline", b.body(), b.issuer, b.signature, keys, e.accepted_name)
    except driftsign.SignatureProblem as x:
        raise HTTPException(400, detail={"message": f"The accepted drift for {e.name.strip()}: {x}"}) from x
    return keys.trusted[b.issuer.key_id][0] if note and b.issuer and b.issuer.key_id in keys.trusted else None


def _check_accepted(e: MatrixEnvironment, baseline: AnySide, bmount: str, bprefix: str) -> None:
    """Accepted drift for other locations would mark the wrong things: refuse it, like the CLI.
    The baseline side isn't checked when it's an export file (the drift file names the Vault's mount)."""
    b = e.accepted
    mount, prefix = e.side.norm()
    wrong = []
    if (b.right.mount.strip("/"), b.right.prefix.strip("/")) != (mount, prefix.strip("/")):
        wrong.append(f"{e.name.strip()} {b.right.mount}/{b.right.prefix}".rstrip("/"))
    if not isinstance(baseline, FileSide) and (b.left.mount.strip("/"), b.left.prefix.strip("/")) != (bmount, bprefix.strip("/")):
        wrong.append(f"the baseline {b.left.mount}/{b.left.prefix}".rstrip("/"))
    if wrong:
        raise HTTPException(400, detail={"message": (
            f"The accepted drift for {e.name.strip()} ({e.accepted_name}) was written for {' and '.join(wrong)}, "
            "not the locations compared here. Use the drift file for this pair, or leave it out.")})
