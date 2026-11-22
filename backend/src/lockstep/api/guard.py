"""LOCKSTEP_READ_ONLY: refuse every write, whatever the user's Vault policies allow."""

from __future__ import annotations

from fastapi import HTTPException

from ..config import Settings


def require_writable(settings: Settings) -> None:
    if settings.read_only:
        raise HTTPException(403, detail={"message": "This Lockstep server is read-only (LOCKSTEP_READ_ONLY): "
                                                    "nothing can be written from here."})
