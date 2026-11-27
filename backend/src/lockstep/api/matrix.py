"""The environment matrix: one baseline compared with several environments at once."""

from __future__ import annotations

from contextlib import AsyncExitStack
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import matrix
from ..config import Settings, get_settings
from ..rules import Rules
from ..session import SessionData, load_session
from ..vault import VaultError
from .compare import Side
from .connections import client_for, get_connection, vault_http_error

router = APIRouter(prefix="/api", tags=["compare"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

Name = Field(min_length=1, max_length=60)


class MatrixEnvironment(BaseModel):
    name: str = Name
    side: Side
    rules: Rules | None = None  # this pair's comparison profile


class MatrixRequest(BaseModel):
    baseline_name: str = Field(default="baseline", min_length=1, max_length=60)
    baseline: Side
    environments: list[MatrixEnvironment] = Field(min_length=1, max_length=matrix.MAX_ENVIRONMENTS)
    include_equal: bool = False


@router.post("/matrix", response_model=matrix.Matrix)
async def compare_matrix(body: MatrixRequest, session: Sess, settings: Conf):
    """Compare the baseline with each environment, each pair under its own profile, and return the
    grid with the odd one out first. Statuses only, never values."""
    names = [body.baseline_name.strip(), *(e.name.strip() for e in body.environments)]
    if len(set(names)) != len(names):
        raise HTTPException(400, detail={"message": "Give the baseline and each environment a different name."})
    bconn = get_connection(session, body.baseline.conn_id)
    conns = [get_connection(session, e.side.conn_id) for e in body.environments]
    bmount, bprefix = body.baseline.norm()
    async with AsyncExitStack() as stack:
        base = await stack.enter_async_context(client_for(bconn, settings))
        envs = []
        for e, conn in zip(body.environments, conns):
            mount, prefix = e.side.norm()
            client = await stack.enter_async_context(client_for(conn, settings))
            envs.append(matrix.EnvInput(name=e.name.strip(), client=client, mount=mount, prefix=prefix, rules=e.rules))
        try:
            return await matrix.run(names[0], base, bmount, bprefix, envs, max_secrets=settings.max_tree_secrets,
                                    include_equal=body.include_equal)
        except VaultError as e:
            raise vault_http_error(e) from e
