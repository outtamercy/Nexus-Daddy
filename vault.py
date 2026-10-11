"""Private Windows-DPAPI storage for Nexus Daddy.

This module owns the encrypted blob only.  Callers use ``api.py``; they never
need to know the on-disk format or read a key file themselves.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


_crypt32 = ctypes.windll.crypt32
_kernel32 = ctypes.windll.kernel32
_crypt32.CryptProtectData.argtypes = (
    ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.POINTER(_DataBlob),
    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob),
)
_crypt32.CryptProtectData.restype = wintypes.BOOL
_crypt32.CryptUnprotectData.argtypes = (
    ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(_DataBlob),
    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob),
)
_crypt32.CryptUnprotectData.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
_kernel32.LocalFree.restype = ctypes.c_void_p
_UI_FORBIDDEN = 0x1


def _blob(data: bytes) -> tuple[_DataBlob, object]:
    buffer = ctypes.create_string_buffer(data or b"\0")
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def _protect(clear: bytes) -> bytes:
    incoming, keepalive = _blob(clear)
    outgoing = _DataBlob()
    if not _crypt32.CryptProtectData(ctypes.byref(incoming), "Nexus Daddy API key", None, None, None, _UI_FORBIDDEN, ctypes.byref(outgoing)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(outgoing.pbData, outgoing.cbData)
    finally:
        _kernel32.LocalFree(outgoing.pbData)


def _unprotect(sealed: bytes) -> bytes:
    incoming, keepalive = _blob(sealed)
    outgoing = _DataBlob()
    description = wintypes.LPWSTR()
    if not _crypt32.CryptUnprotectData(ctypes.byref(incoming), ctypes.byref(description), None, None, None, _UI_FORBIDDEN, ctypes.byref(outgoing)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(outgoing.pbData, outgoing.cbData)
    finally:
        if description:
            _kernel32.LocalFree(description)
        _kernel32.LocalFree(outgoing.pbData)


class Vault:
    """One encrypted key plus an explicit per-requester allow list."""

    # Package Daddy is our first-party downloader. Show it before it asks,
    # otherwise first-run setup turns into a dumb chicken-and-egg trap.
    _KNOWN_REQUESTERS = ("Package Daddy",)

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._raw = self._load()
        self._seed_known_requesters()

    def _seed_known_requesters(self) -> None:
        permissions = self._permissions()
        changed = False
        for requester in self._KNOWN_REQUESTERS:
            if requester not in permissions:
                permissions[requester] = False
                changed = True
        if changed:
            self._save()

    def _load(self) -> dict:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) and payload.get("format") == 1 else {"format": 1}
        except (OSError, ValueError, TypeError):
            return {"format": 1}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".new")
        temporary.write_text(json.dumps(self._raw, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temporary, self.path)

    @property
    def has_key(self) -> bool:
        return bool(self._raw.get("sealed_key"))

    def store(self, key: str) -> None:
        clean = (key or "").strip()
        if not clean:
            raise ValueError("No API key was entered.")
        self._raw["sealed_key"] = base64.b64encode(_protect(clean.encode("utf-8"))).decode("ascii")
        self._save()

    def clear(self) -> None:
        self._raw.pop("sealed_key", None)
        self._save()

    def _permissions(self) -> dict:
        permissions = self._raw.setdefault("permissions", {})
        return permissions if isinstance(permissions, dict) else {}

    def request(self, requester: str) -> bool:
        name = (requester or "").strip() or "Unnamed plugin"
        permissions = self._permissions()
        if name not in permissions:
            permissions[name] = False
            self._save()
        return permissions.get(name) is True

    def set_allowed(self, requester: str, allowed: bool) -> None:
        self._permissions()[(requester or "").strip() or "Unnamed plugin"] = bool(allowed)
        self._save()

    def permissions(self) -> dict[str, bool]:
        return {str(name): bool(value) for name, value in self._permissions().items()}

    def key_for(self, requester: str) -> str:
        if not self.has_key or not self.request(requester):
            return ""
        try:
            sealed = base64.b64decode(self._raw["sealed_key"].encode("ascii"))
            return _unprotect(sealed).decode("utf-8").strip()
        except (OSError, ValueError, UnicodeDecodeError):
            return ""

