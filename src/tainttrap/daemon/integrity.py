"""Policy pinning, out-of-band confirmation and `reload` (spec FR-022, FR-032; T061).

Human-only admin ops need a 6-digit code that the daemon delivers only through an OS
notification or dialog. The code is never returned over a socket or logged, except in the
case where no GUI notifier exists: then daemon reloads and approvals are refused outright.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from tainttrap.core import paths
from tainttrap.core.policy import PolicyError, load_policy, policy_hash
from tainttrap.core.registry import Registry

if TYPE_CHECKING:
    from tainttrap.daemon.server import Daemon

MAX_ATTEMPTS = 3
NO_CHANNEL_RELOAD = (
    "no secure confirmation channel (no GUI notifier); edit the policy file yourself "
    "(owner-only) and restart the daemon: tainttrap daemon stop && tainttrap daemon start"
)
CHALLENGE_TTL_S = 120


class ConfirmProvider(Protocol):
    name: str

    def deliver(self, code: str, purpose: str) -> bool:
        """Show the code to the human out of band. False if the channel is unavailable."""
        ...


class NotifierProvider:
    name = "notifier"

    def notify(self, message: str) -> None:
        """Best-effort heads-up without a code (macOS notification / notify-send)."""
        try:
            if sys.platform == "darwin" and shutil.which("osascript"):
                safe = message.replace('"', "'")
                subprocess.Popen(
                    ["osascript", "-e", f'display notification "{safe}" with title "TaintTrap"'],  # noqa: S603,S607
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            elif shutil.which("notify-send") and (
                os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
            ):
                subprocess.Popen(
                    ["notify-send", "TaintTrap", message],  # noqa: S603,S607
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
        except OSError:
            pass

    def deliver(self, code: str, purpose: str) -> bool:
        text = f"TaintTrap confirmation code: {code}\\n({purpose})"
        try:
            if sys.platform == "darwin" and shutil.which("osascript"):
                script = (
                    f'display dialog "{text}" with title "TaintTrap" '
                    'buttons {"OK"} default button "OK" giving up after 120'
                )
                subprocess.Popen(
                    ["osascript", "-e", script],
                    stdout=subprocess.DEVNULL,  # noqa: S603,S607
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return True
            if shutil.which("powershell.exe"):
                ps = f"[System.Windows.MessageBox]::Show('TaintTrap code: {code}','TaintTrap')"
                subprocess.Popen(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-Command",  # noqa: S603,S607
                        "Add-Type -AssemblyName PresentationFramework;" + ps,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return True
            if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
                for cmd in (
                    ["zenity", "--info", "--title=TaintTrap", f"--text=TaintTrap code: {code}"],
                    ["notify-send", "TaintTrap", f"Confirmation code: {code}"],
                ):
                    if shutil.which(cmd[0]):
                        subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,  # noqa: S603
                            stderr=subprocess.DEVNULL,
                            start_new_session=True,
                        )
                        return True
        except OSError:
            return False
        return False


@dataclass
class Challenge:
    purpose: str
    code_hash: bytes
    expires_at: float
    channel: str
    attempts: int = 0


def _hash(code: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", code.encode(), salt, 50_000)


@dataclass
class Integrity:
    provider: ConfirmProvider = field(default_factory=NotifierProvider)
    pinned_hash: str = ""
    _salt: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    _challenges: dict[str, Challenge] = field(default_factory=dict)

    def new_challenge(self, purpose: str) -> tuple[str, str, str | None]:
        """Returns (challenge_id, channel, undelivered_code_or_None). Callers must never show an
        undelivered code; they refuse the operation instead."""
        code = f"{secrets.randbelow(10**6):06d}"
        cid = secrets.token_hex(8)
        delivered = self.provider.deliver(code, purpose)
        channel = self.provider.name if delivered else "undelivered"
        self._challenges[cid] = Challenge(
            purpose, _hash(code, self._salt), time.time() + CHALLENGE_TTL_S, channel
        )
        return cid, channel, (None if delivered else code)

    def forget(self, cid: str) -> None:
        self._challenges.pop(cid, None)

    def verify(self, cid: str, code: str, purpose: str) -> tuple[bool, str]:
        ch = self._challenges.get(cid)
        if ch is None or ch.purpose != purpose:
            return False, "unknown challenge"
        if time.time() > ch.expires_at:
            del self._challenges[cid]
            return False, "challenge expired"
        if hmac.compare_digest(_hash(str(code), self._salt), ch.code_hash):
            del self._challenges[cid]
            return True, ch.channel
        ch.attempts += 1
        if ch.attempts >= MAX_ATTEMPTS:
            del self._challenges[cid]
            return False, "too many wrong codes; request cancelled"
        return False, f"wrong code ({MAX_ATTEMPTS - ch.attempts} attempts left)"


def register(daemon: Daemon, integrity: Integrity) -> None:
    from tainttrap.daemon.server import RequestError

    integrity.pinned_hash = policy_hash(daemon.policy)

    async def reload_challenge(req: dict[str, Any]) -> dict[str, Any]:
        try:
            new = load_policy(paths.policy_file())
            Registry.load(paths.user_registry_file())
        except PolicyError as e:
            return {"valid": False, "problems": e.problems}
        except Exception as e:  # noqa: BLE001 - a broken registry file is a validation error
            return {"valid": False, "problems": [f"registry: {e}"]}
        cid, channel, fallback_code = integrity.new_challenge("reload policy")
        if fallback_code is not None:
            # No out-of-band channel: never show the code where the agent could read it.
            integrity.forget(cid)
            return {"valid": True, "no_channel": True, "detail": NO_CHANNEL_RELOAD}
        return {
            "valid": True,
            "challenge_id": cid,
            "channel": channel,
            "new_hash": policy_hash(new),
            "current_hash": integrity.pinned_hash,
        }

    async def reload(req: dict[str, Any]) -> dict[str, Any]:
        ok, detail = integrity.verify(
            str(req.get("challenge_id")), str(req.get("code")), "reload policy"
        )
        if not ok:
            daemon.log_writer.write(daemon._entry("policy_reload_refused", detail=detail))
            raise RequestError("confirmation_failed", detail)
        try:
            new = load_policy(paths.policy_file())
            registry = Registry.load(paths.user_registry_file())
        except PolicyError as e:
            daemon.log_writer.write(
                daemon._entry("policy_reload_refused", detail="; ".join(e.problems))
            )
            raise RequestError("invalid_policy", "; ".join(e.problems)) from e
        daemon.engine.registry = registry
        daemon.apply_policy(new)
        integrity.pinned_hash = policy_hash(new)
        daemon.log_writer.write(
            daemon._entry("policy_reloaded", detail=f"confirm_channel: {detail}")
        )
        return {"policy_hash": integrity.pinned_hash, "mode": new.mode.value}

    daemon.admin_handlers["reload_challenge"] = reload_challenge
    daemon.admin_handlers["reload"] = reload
