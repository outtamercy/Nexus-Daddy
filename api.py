"""The small public surface other first-party plugins may use.

Public v2 requests work without a stored key.  A caller requesting the key
is recorded in Nexus Daddy and gets nothing until the user explicitly allows
it there.  No caller receives the key by accident.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .vault import Vault


GRAPHQL = "https://api.nexusmods.com/v2/graphql"
APPLICATION_NAME = "Nexus Daddy"
APPLICATION_VERSION = "0.2.0"


class NexusDaddyError(RuntimeError):
    pass


def _archive_suffix(path: Path) -> str:
    """Identify the archive Daddy just wrote when Nexus omitted its suffix."""
    try:
        with path.open("rb") as stream:
            signature = stream.read(8)
    except OSError:
        return ""
    if signature.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return ".zip"
    if signature.startswith(b"7z\xbc\xaf\x27\x1c"):
        return ".7z"
    if signature.startswith(b"Rar!\x1a\x07"):
        return ".rar"
    return ""


def storage(organizer) -> Path:
    try:
        return Path(organizer.pluginDataPath()) / "nexus_daddy" / "vault.json"
    except Exception:
        return Path(__file__).parent / "vault.json"


def vault(organizer) -> Vault:
    return Vault(storage(organizer))


def key(organizer, requester: str) -> str:
    return vault(organizer).key_for(requester)


class NexusClient:
    """Qt-backed Nexus v2 GraphQL client. TLS verification is never disabled."""

    def __init__(self, api_key: str = "", timeout_seconds: int = 15):
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def _request_json(self, url: str, *, body: bytes | None = None,
                      headers: dict[str, str] | None = None):
        # This file also gets imported outside MO2. Networking only exists
        # when the actual MO2 Qt app is alive, so don't blow up just loading it.
        from PyQt6.QtCore import QEventLoop, QTimer, QUrl
        from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest

        request = QNetworkRequest(QUrl(url))
        request.setRawHeader(b"Accept", b"application/json")
        # These are the client IDs Nexus gave us. Don't cosplay another app
        # just because its headers are easy to find.
        request.setRawHeader(b"User-Agent", b"Nexus-Daddy-MO2/" + APPLICATION_VERSION.encode("ascii"))
        request.setRawHeader(b"Application-Name", APPLICATION_NAME.encode("utf-8"))
        request.setRawHeader(b"Application-Version", APPLICATION_VERSION.encode("ascii"))
        for name, value in (headers or {}).items():
            request.setRawHeader(name.encode("ascii"), value.encode("utf-8"))
        manager = QNetworkAccessManager()
        reply = manager.post(request, body) if body is not None else manager.get(request)
        loop = QEventLoop()
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        reply.finished.connect(loop.quit)
        timer.start(max(1, self.timeout_seconds * 1000))
        loop.exec()
        if not reply.isFinished():
            reply.abort()
            raise NexusDaddyError("Nexus request timed out.")
        status = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
        try:
            status = int(status) if status is not None else None
        except (TypeError, ValueError):
            status = None
        if reply.error() != QNetworkReply.NetworkError.NoError or (status is not None and status >= 400):
            detail = reply.errorString() or "Nexus did not accept the request."
            if status == 403 and "/download_link.json" in url:
                detail = (
                    "Nexus refused to issue a direct download link for this file. "
                    "This account or file needs Nexus's own manager/SSO download authorization; "
                    "Daddy did not download anything."
                )
            raise NexusDaddyError(f"Nexus request failed{f' ({status})' if status else ''}: {detail}")
        try:
            parsed = json.loads(bytes(reply.readAll()).decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise NexusDaddyError("Nexus returned unreadable data.") from exc
        return parsed

    def graphql(self, query: str, variables: dict | None = None) -> dict:
        payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
        # Public GraphQL lookups don't need the key. Keep the damn thing off
        # ordinary requests on purpose.
        parsed = self._request_json(GRAPHQL, body=payload, headers={"Content-Type": "application/json"})
        if parsed.get("errors"):
            raise NexusDaddyError("Nexus rejected the query: " + str(parsed["errors"][0]))
        return parsed.get("data") or {}

    def game_id(self, domain: str) -> int | None:
        data = self.graphql(
            "query($domain: String!) { game(domainName: $domain) { id } }",
            {"domain": domain},
        )
        value = (data.get("game") or {}).get("id")
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _require_key(self) -> None:
        if not self.api_key:
            raise NexusDaddyError("This action needs a Nexus API key that you have allowed for this plugin.")

    def files(self, game_domain: str, mod_id: int) -> list[dict]:
        """List a mod's file records through the authenticated v1 API."""
        self._require_key()
        parsed = self._request_json(
            f"https://api.nexusmods.com/v1/games/{game_domain}/mods/{int(mod_id)}/files.json",
            headers={"apikey": self.api_key},
        )
        files = parsed.get("files") or []
        return [entry for entry in files if isinstance(entry, dict)]

    def download_links(self, game_domain: str, mod_id: int, file_id: int) -> list[str]:
        """Ask Nexus for this user's permitted CDN link(s), without guessing."""
        self._require_key()
        parsed = self._request_json(
            f"https://api.nexusmods.com/v1/games/{game_domain}/mods/{int(mod_id)}/files/{int(file_id)}/download_link.json",
            headers={"apikey": self.api_key},
        )
        entries = parsed if isinstance(parsed, list) else parsed.get("links") or []
        links = []
        for entry in entries:
            value = entry.get("URI") if isinstance(entry, dict) else entry
            if isinstance(value, str) and value.startswith("https://"):
                links.append(value)
        if not links:
            raise NexusDaddyError("Nexus did not grant a direct download link for this file. Its download rules still apply.")
        return links

    def download_to(self, url: str, destination: str | Path) -> Path:
        """Download one Nexus-provided CDN URL without leaking the API key.

        The key is sent only to api.nexusmods.com when obtaining the link.
        The resulting CDN request has no credential header and keeps Qt's
        normal certificate validation and no-less-safe redirect policy.
        """
        from PyQt6.QtCore import QEventLoop, QTimer, QUrl
        from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest

        target = Path(destination)
        if target.exists():
            raise NexusDaddyError("Refusing to overwrite the chosen download destination.")
        if not target.parent.is_dir():
            raise NexusDaddyError("The chosen download folder is unavailable.")
        partial = target.with_name(target.name + ".nexus-daddy-part")
        if partial.exists():
            raise NexusDaddyError("A previous Nexus Daddy partial download is still present. Review or remove it before retrying.")
        created_partial = False
        try:
            with partial.open("xb") as stream:
                created_partial = True
                request = QNetworkRequest(QUrl(url))
                request.setRawHeader(b"User-Agent", b"Nexus-Daddy-MO2/" + APPLICATION_VERSION.encode("ascii"))
                request.setRawHeader(b"Application-Name", APPLICATION_NAME.encode("utf-8"))
                request.setRawHeader(b"Application-Version", APPLICATION_VERSION.encode("ascii"))
                request.setAttribute(QNetworkRequest.Attribute.RedirectPolicyAttribute, QNetworkRequest.RedirectPolicy.NoLessSafeRedirectPolicy)
                manager = QNetworkAccessManager()
                reply = manager.get(request)
                loop = QEventLoop()
                timer = QTimer()
                timer.setSingleShot(True)

                def drain():
                    stream.write(bytes(reply.readAll()))

                timer.timeout.connect(loop.quit)
                def drain_and_extend_timeout():
                    drain()
                    # Big archives can outlive the connection timeout, but
                    # they still need to keep moving. No zombie downloads.
                    timer.start(max(1, self.timeout_seconds * 1000))

                reply.readyRead.connect(drain_and_extend_timeout)
                reply.finished.connect(loop.quit)
                timer.start(max(1, self.timeout_seconds * 1000))
                loop.exec()
                drain()
                if not reply.isFinished():
                    reply.abort()
                    raise NexusDaddyError("Download timed out. The partial file was removed.")
                if reply.error() != QNetworkReply.NetworkError.NoError:
                    raise NexusDaddyError("Download failed: " + reply.errorString())
            final_target = target
            # Path thinks the final .0 in "Plugin 1.0.0" is an extension.
            # Cute, but wrong. Only a real archive suffix counts here.
            if target.suffix.lower() not in {".zip", ".7z", ".rar"}:
                suffix = _archive_suffix(partial)
                if suffix:
                    final_target = target.with_name(target.name + suffix)
            if final_target.exists():
                raise NexusDaddyError("Download finished, but Daddy refused to overwrite an existing archive.")
            os.rename(partial, final_target)
            return final_target
        except (OSError, NexusDaddyError):
            if created_partial:
                try:
                    partial.unlink(missing_ok=True)
                except OSError:
                    pass
            raise


def client(organizer, requester: str = "", require_key: bool = False) -> NexusClient | None:
    api_key = key(organizer, requester) if require_key else ""
    if require_key and not api_key:
        return None
    return NexusClient(api_key)

