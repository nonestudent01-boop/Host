"""
UZL BOT HOST - Advanced Admin System
Single Python backend module.

Designed to be integrated with an existing UZL BOT HOST application.
This module provides:
- Server-side RBAC
- Admin API endpoints
- Safe bot-scoped file management
- Audit logging
- Broadcast queue architecture
- Admin slash-command routing
- Secret redaction
- Rate limiting hooks

Dependencies:
    pip install flask

Production integration should connect these adapters to the existing
database, authentication, bot runner, deployment system and notification
provider.
"""

from __future__ import annotations

import json
import os
import queue
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from flask import Flask, jsonify, request, send_file

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

BOT_STORAGE_ROOT = Path(
    os.environ.get("BOT_STORAGE_ROOT", "./storage/bots")
).resolve()

MAX_FILE_SIZE = int(
    os.environ.get("MAX_FILE_SIZE", str(50 * 1024 * 1024))
)

BROADCAST_BATCH_SIZE = int(os.environ.get("BROADCAST_BATCH_SIZE", "25"))
BROADCAST_MAX_RETRIES = int(os.environ.get("BROADCAST_MAX_RETRIES", "5"))
BROADCAST_BACKOFF_BASE = float(
    os.environ.get("BROADCAST_BACKOFF_BASE_MS", "2000")
) / 1000.0

SUPERADMIN_IDS = {
    x.strip()
    for x in os.environ.get("SUPERADMIN_IDS", "").split(",")
    if x.strip()
}

ALL_PERMISSIONS = {
    "users.view",
    "users.manage",
    "bots.view",
    "bots.manage",
    "files.view",
    "files.download",
    "files.upload",
    "files.modify",
    "files.delete",
    "logs.view",
    "deployments.manage",
    "broadcast.send",
    "runners.manage",
    "settings.manage",
}

DEFAULT_ADMIN_PERMISSIONS = {
    x.strip()
    for x in os.environ.get(
        "ADMIN_DEFAULT_PERMISSIONS",
        "users.view,bots.view,files.view,files.download,logs.view"
    ).split(",")
    if x.strip()
}

SECRET_KEYS = {
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "session_secret",
    "private_key",
    "encryption_key",
    "runner_private_key",
    "secret",
}


# ============================================================
# IN-MEMORY DEMO STORES
# Replace with existing project's database repositories.
# ============================================================

USERS: Dict[str, Dict[str, Any]] = {}
BOTS: Dict[str, Dict[str, Any]] = {}
AUDIT_LOGS: list[dict[str, Any]] = []
BROADCASTS: Dict[str, Dict[str, Any]] = {}
BROADCAST_DELIVERIES: Dict[str, list[dict[str, Any]]] = {}
ADMIN_PERMISSIONS: Dict[str, set[str]] = {}

BROADCAST_QUEUE: "queue.Queue[str]" = queue.Queue()


# ============================================================
# UTILITY
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_safe(value: Any) -> Any:
    """Recursively redact known secret fields."""
    if isinstance(value, dict):
        return {
            k: ("---" if k.lower() in SECRET_KEYS else json_safe(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    return value


def get_current_admin() -> Optional[dict[str, Any]]:
    """
    Replace this with the existing authenticated-session/identity system.

    SECURITY:
    Never use a client-supplied role as authorization.
    """
    admin_id = request.headers.get("X-Authenticated-User")
    if not admin_id:
        return None

    role = "SUPERADMIN" if admin_id in SUPERADMIN_IDS else "ADMIN"
    permissions = (
        ALL_PERMISSIONS
        if role == "SUPERADMIN"
        else ADMIN_PERMISSIONS.get(admin_id, DEFAULT_ADMIN_PERMISSIONS)
    )

    return {
        "id": admin_id,
        "role": role,
        "permissions": set(permissions),
    }


def has_permission(admin: dict[str, Any], permission: str) -> bool:
    return (
        admin["role"] == "SUPERADMIN"
        or permission in admin["permissions"]
    )


def audit(
    admin_id: str,
    action: str,
    *,
    target_user_id: Optional[str] = None,
    bot_id: Optional[str] = None,
    file_path: Optional[str] = None,
    success: bool = True,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    # Never store file contents or secret values.
    AUDIT_LOGS.append(
        {
            "id": str(uuid.uuid4()),
            "adminId": admin_id,
            "action": action,
            "targetUserId": target_user_id,
            "botId": bot_id,
            "filePath": file_path,
            "timestamp": utc_now(),
            "success": bool(success),
            "metadata": json_safe(metadata or {}),
        }
    )


def require_permission(permission: str):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            admin = get_current_admin()

            if not admin:
                return jsonify({"error": "Permission denied"}), 403

            if not has_permission(admin, permission):
                audit(
                    admin["id"],
                    "PERMISSION_DENIED",
                    success=False,
                    metadata={"requiredPermission": permission},
                )
                return jsonify({"error": "Permission denied"}), 403

            request.admin = admin
            return fn(*args, **kwargs)

        return wrapped

    return decorator


# ============================================================
# OWNERSHIP / PATH SECURITY
# ============================================================

SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def validate_id(value: str) -> bool:
    return bool(value and SAFE_ID.fullmatch(value))


def bot_record(user_id: str, bot_id: str) -> Optional[dict[str, Any]]:
    if not validate_id(user_id) or not validate_id(bot_id):
        return None

    bot = BOTS.get(bot_id)

    if not bot:
        return None

    if str(bot.get("userId")) != str(user_id):
        return None

    return bot


def bot_root(user_id: str, bot_id: str) -> Path:
    """
    Resolve only the selected user's selected bot directory.
    Never accepts an arbitrary filesystem path from the client.
    """
    if not validate_id(user_id) or not validate_id(bot_id):
        raise ValueError("Invalid identifier")

    root = (BOT_STORAGE_ROOT / user_id / bot_id).resolve()

    try:
        root.relative_to(BOT_STORAGE_ROOT)
    except ValueError:
        raise ValueError("Storage escape detected")

    return root


def safe_bot_path(
    user_id: str,
    bot_id: str,
    relative_path: str,
) -> tuple[Path, Path]:
    if not isinstance(relative_path, str):
        raise ValueError("Invalid path")

    if not relative_path:
        relative_path = "."

    if "\x00" in relative_path:
        raise ValueError("Invalid path")

    # Normalize separators and reject traversal.
    normalized = relative_path.replace("\\", "/")

    if normalized.startswith("/"):
        raise ValueError("Absolute paths are forbidden")

    parts = [p for p in normalized.split("/") if p not in ("", ".")]

    if ".." in parts:
        raise ValueError("Path traversal detected")

    root = bot_root(user_id, bot_id)
    target = (root / Path(*parts)).resolve()

    try:
        target.relative_to(root)
    except ValueError:
        raise ValueError("Storage escape detected")

    # Symlink escape protection.
    if target.exists():
        real_target = target.resolve()
        try:
            real_target.relative_to(root)
        except ValueError:
            raise ValueError("Symlink escape detected")

    return root, target


# ============================================================
# RATE LIMITER
# ============================================================

class SimpleRateLimiter:
    def __init__(self, limit: int = 30, window: int = 60):
        self.limit = limit
        self.window = window
        self.events: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()

        with self.lock:
            values = self.events.setdefault(key, [])
            values[:] = [
                timestamp
                for timestamp in values
                if now - timestamp < self.window
            ]

            if len(values) >= self.limit:
                return False

            values.append(now)
            return True


ADMIN_RATE_LIMITER = SimpleRateLimiter(60, 60)


@app.before_request
def admin_rate_limit():
    if request.path.startswith("/api/admin"):
        admin = get_current_admin()
        if admin and not ADMIN_RATE_LIMITER.allow(admin["id"]):
            return jsonify({"error": "Rate limit exceeded"}), 429


# ============================================================
# SESSION / ADMIN INFO
# ============================================================

@app.get("/api/admin/session")
@require_permission("users.view")
def admin_session():
    admin = request.admin
    return jsonify(
        {
            "user": {"id": admin["id"]},
            "role": admin["role"],
            "permissions": sorted(admin["permissions"]),
        }
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.get("/api/admin/stats")
@require_permission("users.view")
def admin_stats():
    running = sum(
        1 for bot in BOTS.values()
        if str(bot.get("status", "")).upper() == "RUNNING"
    )

    return jsonify(
        {
            "totalUsers": len(USERS),
            "activeUsers": sum(
                1 for u in USERS.values()
                if str(u.get("status", "")).upper() == "ACTIVE"
            ),
            "totalBots": len(BOTS),
            "runningBots": running,
            "failedDeployments": 0,
            "onlineRunners": 0,
            "storageUsage": "0 B",
            "broadcastsSent": sum(
                b.get("successCount", 0)
                for b in BROADCASTS.values()
            ),
        }
    )


# ============================================================
# USERS
# ============================================================

@app.get("/api/admin/users")
@require_permission("users.view")
def list_users():
    search = request.args.get("search", "").lower()
    page = max(1, int(request.args.get("page", "1")))
    limit = min(100, max(1, int(request.args.get("limit", "20"))))

    rows = list(USERS.values())

    if search:
        rows = [
            u for u in rows
            if search in str(u.get("username", "")).lower()
            or search in str(u.get("email", "")).lower()
            or search in str(u.get("id", "")).lower()
        ]

    start = (page - 1) * limit
    return jsonify(
        {
            "items": rows[start:start + limit],
            "page": page,
            "limit": limit,
            "total": len(rows),
        }
    )


@app.get("/api/admin/users/<user_id>")
@require_permission("users.view")
def get_user(user_id: str):
    user = USERS.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    audit(request.admin["id"], "USER_VIEW", target_user_id=user_id)

    return jsonify(
        {
            k: v
            for k, v in user.items()
            if k.lower() not in SECRET_KEYS
        }
    )


@app.get("/api/admin/users/<user_id>/bots")
@require_permission("bots.view")
def get_user_bots(user_id: str):
    if user_id not in USERS:
        return jsonify({"error": "User not found"}), 404

    rows = [
        bot
        for bot in BOTS.values()
        if str(bot.get("userId")) == str(user_id)
    ]

    return jsonify({"items": rows})


# ============================================================
# BOT MANAGEMENT
# ============================================================

@app.get("/api/admin/bots")
@require_permission("bots.view")
def list_bots():
    return jsonify({"items": list(BOTS.values())})


@app.get("/api/admin/users/<user_id>/bots/<bot_id>")
@require_permission("bots.view")
def get_bot(user_id: str, bot_id: str):
    bot = bot_record(user_id, bot_id)

    if not bot:
        return jsonify({"error": "Bot not found"}), 404

    audit(
        request.admin["id"],
        "BOT_VIEW",
        target_user_id=user_id,
        bot_id=bot_id,
    )

    return jsonify(json_safe(bot))


def perform_bot_action(user_id: str, bot_id: str, action: str):
    bot = bot_record(user_id, bot_id)

    if not bot:
        return jsonify({"error": "Bot not found"}), 404

    # Connect these operations to the existing runner/deployment service.
    if action == "start":
        bot["status"] = "RUNNING"
    elif action == "stop":
        bot["status"] = "STOPPED"
    elif action == "restart":
        bot["status"] = "RUNNING"
    elif action == "redeploy":
        bot["deploymentStatus"] = "QUEUED"

    audit(
        request.admin["id"],
        f"BOT_{action.upper()}",
        target_user_id=user_id,
        bot_id=bot_id,
    )

    return jsonify({"ok": True, "action": action, "bot": json_safe(bot)})


@app.post("/api/admin/users/<user_id>/bots/<bot_id>/start")
@require_permission("bots.manage")
def start_bot(user_id, bot_id):
    return perform_bot_action(user_id, bot_id, "start")


@app.post("/api/admin/users/<user_id>/bots/<bot_id>/stop")
@require_permission("bots.manage")
def stop_bot(user_id, bot_id):
    return perform_bot_action(user_id, bot_id, "stop")


@app.post("/api/admin/users/<user_id>/bots/<bot_id>/restart")
@require_permission("bots.manage")
def restart_bot(user_id, bot_id):
    return perform_bot_action(user_id, bot_id, "restart")


@app.post("/api/admin/users/<user_id>/bots/<bot_id>/redeploy")
@require_permission("bots.manage")
def redeploy_bot(user_id, bot_id):
    return perform_bot_action(user_id, bot_id, "redeploy")


# ============================================================
# FILE MANAGER
# ============================================================

@app.get("/api/admin/users/<user_id>/bots/<bot_id>/files")
@require_permission("files.view")
def list_files(user_id: str, bot_id: str):
    path = request.args.get("path", "")

    try:
        root, target = safe_bot_path(user_id, bot_id, path)

        if not target.exists():
            return jsonify({"error": "Path not found"}), 404

        if not target.is_dir():
            return jsonify({"error": "Not a directory"}), 400

        items = []

        for item in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            try:
                relative = item.relative_to(root).as_posix()
                stat = item.stat()

                items.append(
                    {
                        "name": item.name,
                        "type": "folder" if item.is_dir() else "file",
                        "isDirectory": item.is_dir(),
                        "size": stat.st_size if item.is_file() else None,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime,
                            timezone.utc,
                        ).isoformat(),
                        "path": relative,
                    }
                )
            except (OSError, ValueError):
                continue

        audit(
            request.admin["id"],
            "ADMIN_FILE_VIEW",
            target_user_id=user_id,
            bot_id=bot_id,
            file_path=path,
        )

        return jsonify({"items": items})

    except ValueError as exc:
        audit(
            request.admin["id"],
            "ADMIN_FILE_VIEW",
            target_user_id=user_id,
            bot_id=bot_id,
            file_path=path,
            success=False,
        )
        return jsonify({"error": str(exc)}), 400


@app.get("/api/admin/users/<user_id>/bots/<bot_id>/files/content")
@require_permission("files.view")
def read_file(user_id: str, bot_id: str):
    path = request.args.get("path", "")

    try:
        root, target = safe_bot_path(user_id, bot_id, path)

        if not target.exists() or not target.is_file():
            return jsonify({"error": "File not found"}), 404

        if target.stat().st_size > MAX_FILE_SIZE:
            return jsonify({"error": "File too large"}), 413

        raw = target.read_bytes()

        # Do not expose likely binary files through the text API.
        if b"\x00" in raw:
            return jsonify({"error": "Binary file"}), 415

        content = raw.decode("utf-8", errors="replace")

        audit(
            request.admin["id"],
            "ADMIN_FILE_VIEW",
            target_user_id=user_id,
            bot_id=bot_id,
            file_path=path,
        )

        return jsonify({"content": content})

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/admin/users/<user_id>/bots/<bot_id>/files/download")
@require_permission("files.download")
def download_file(user_id: str, bot_id: str):
    path = request.args.get("path", "")

    try:
        _, target = safe_bot_path(user_id, bot_id, path)

        if not target.exists() or not target.is_file():
            return jsonify({"error": "File not found"}), 404

        audit(
            request.admin["id"],
            "ADMIN_FILE_DOWNLOAD",
            target_user_id=user_id,
            bot_id=bot_id,
            file_path=path,
        )

        return send_file(target, as_attachment=True)

    except ValueError as exc:
        audit(
            request.admin["id"],
            "ADMIN_FILE_DOWNLOAD",
            target_user_id=user_id,
            bot_id=bot_id,
            file_path=path,
            success=False,
        )
        return jsonify({"error": str(exc)}), 400


@app.post("/api/admin/users/<user_id>/bots/<bot_id>/files")
@require_permission("files.modify")
def modify_file(user_id: str, bot_id: str):
    data = request.get_json(silent=True) or {}
    operation = data.get("operation")
    path = data.get("path", "")

    try:
        root, target = safe_bot_path(user_id, bot_id, path)

        if operation == "create":
            if target.exists():
                return jsonify({"error": "Already exists"}), 409
            target.parent.mkdir(parents=True, exist_ok=True)
            target.touch()
            action = "ADMIN_FILE_EDIT"

        elif operation == "mkdir":
            if target.exists():
                return jsonify({"error": "Already exists"}), 409
            target.mkdir(parents=True)
            action = "ADMIN_FILE_EDIT"

        elif operation in {"write", "upload"}:
            content = data.get("content", "")

            if not isinstance(content, str):
                return jsonify({"error": "Invalid content"}), 400

            raw = content.encode("utf-8")

            if len(raw) > MAX_FILE_SIZE:
                return jsonify({"error": "File too large"}), 413

            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            action = (
                "ADMIN_FILE_UPLOAD"
                if operation == "upload"
                else "ADMIN_FILE_EDIT"
            )

        elif operation == "rename":
            new_name = data.get("newName", "")

            if (
                not new_name
                or "/" in new_name
                or "\\" in new_name
                or new_name in {".", ".."}
            ):
                return jsonify({"error": "Invalid name"}), 400

            if not target.exists():
                return jsonify({"error": "File not found"}), 404

            new_target = (target.parent / new_name).resolve()

            try:
                new_target.relative_to(root)
            except ValueError:
                return jsonify({"error": "Storage escape detected"}), 400

            target.rename(new_target)
            action = "ADMIN_FILE_RENAME"

        else:
            return jsonify({"error": "Unsupported operation"}), 400

        audit(
            request.admin["id"],
            action,
            target_user_id=user_id,
            bot_id=bot_id,
            file_path=path,
        )

        return jsonify({"ok": True})

    except ValueError as exc:
        audit(
            request.admin["id"],
            "ADMIN_FILE_EDIT",
            target_user_id=user_id,
            bot_id=bot_id,
            file_path=path,
            success=False,
        )
        return jsonify({"error": str(exc)}), 400


@app.delete("/api/admin/users/<user_id>/bots/<bot_id>/files")
@require_permission("files.delete")
def delete_file(user_id: str, bot_id: str):
    data = request.get_json(silent=True) or {}
    path = data.get("path", "")

    try:
        root, target = safe_bot_path(user_id, bot_id, path)

        if target == root:
            return jsonify({"error": "Cannot delete bot root"}), 400

        if not target.exists():
            return jsonify({"error": "Not found"}), 404

        if target.is_dir():
            import shutil
            shutil.rmtree(target)
        else:
            target.unlink()

        audit(
            request.admin["id"],
            "ADMIN_FILE_DELETE",
            target_user_id=user_id,
            bot_id=bot_id,
            file_path=path,
        )

        return jsonify({"ok": True})

    except ValueError as exc:
        audit(
            request.admin["id"],
            "ADMIN_FILE_DELETE",
            target_user_id=user_id,
            bot_id=bot_id,
            file_path=path,
            success=False,
        )
        return jsonify({"error": str(exc)}), 400


# ============================================================
# USER STATUS
# ============================================================

@app.post("/api/admin/users/<user_id>/suspend")
@require_permission("users.manage")
def suspend_user(user_id: str):
    user = USERS.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    user["status"] = "SUSPENDED"

    audit(
        request.admin["id"],
        "USER_SUSPEND",
        target_user_id=user_id,
    )

    return jsonify({"ok": True})


@app.post("/api/admin/users/<user_id>/unsuspend")
@require_permission("users.manage")
def unsuspend_user(user_id: str):
    user = USERS.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    user["status"] = "ACTIVE"

    audit(
        request.admin["id"],
        "USER_UNSUSPEND",
        target_user_id=user_id,
    )

    return jsonify({"ok": True})


# ============================================================
# BROADCAST PROVIDER
# ============================================================

class BroadcastProvider:
    """
    Provider abstraction.

    Replace this implementation with the platform's configured
    notification provider. Provider-specific authentication and
    limits must remain server-side.
    """

    name = "platform"

    def send(self, recipient: dict[str, Any], broadcast: dict[str, Any]) -> dict[str, Any]:
        # Connect to the existing notification/channel provider here.
        return {
            "success": True,
            "provider": self.name,
            "recipientId": recipient["id"],
        }


PROVIDER = BroadcastProvider()


# ============================================================
# BROADCAST QUEUE
# ============================================================

def eligible_recipients(audience_type: str) -> list[dict[str, Any]]:
    users = list(USERS.values())

    if audience_type == "ALL_USERS":
        return users

    if audience_type == "ACTIVE_USERS":
        return [
            u for u in users
            if str(u.get("status", "")).upper() == "ACTIVE"
        ]

    if audience_type == "SUSPENDED_USERS":
        return [
            u for u in users
            if str(u.get("status", "")).upper() == "SUSPENDED"
        ]

    if audience_type == "USERS_WITH_BOTS":
        ids = {str(b.get("userId")) for b in BOTS.values()}
        return [u for u in users if str(u.get("id")) in ids]

    if audience_type == "USERS_WITH_RUNNING_BOTS":
        ids = {
            str(b.get("userId"))
            for b in BOTS.values()
            if str(b.get("status", "")).upper() == "RUNNING"
        }
        return [u for u in users if str(u.get("id")) in ids]

    return []


def process_broadcast(broadcast_id: str) -> None:
    broadcast = BROADCASTS.get(broadcast_id)

    if not broadcast:
        return

    if broadcast["status"] == "CANCELLED":
        return

    broadcast["status"] = "PROCESSING"
    broadcast["startedAt"] = utc_now()

    recipients = eligible_recipients(broadcast["audienceType"])

    deliveries = BROADCAST_DELIVERIES.setdefault(
        broadcast_id, []
    )

    for index in range(0, len(recipients), BROADCAST_BATCH_SIZE):
        batch = recipients[index:index + BROADCAST_BATCH_SIZE]

        for recipient in batch:
            if broadcast["status"] == "CANCELLED":
                return

            success = False
            last_error = None

            for attempt in range(BROADCAST_MAX_RETRIES):
                try:
                    result = PROVIDER.send(recipient, broadcast)
                    success = bool(result.get("success"))
                    if success:
                        break
                except Exception as exc:
                    last_error = str(exc)

                time.sleep(
                    BROADCAST_BACKOFF_BASE * (2 ** attempt)
                )

            deliveries.append(
                {
                    "id": str(uuid.uuid4()),
                    "broadcastId": broadcast_id,
                    "recipientId": recipient.get("id"),
                    "success": success,
                    "attempts": attempt + 1,
                    "error": last_error,
                    "sentAt": utc_now() if success else None,
                }
            )

            if success:
                broadcast["successCount"] += 1
            else:
                broadcast["failureCount"] += 1

    if broadcast["status"] != "CANCELLED":
        if broadcast["failureCount"] == 0:
            broadcast["status"] = "COMPLETED"
        elif broadcast["successCount"] > 0:
            broadcast["status"] = "PARTIAL"
        else:
            broadcast["status"] = "FAILED"

        broadcast["completedAt"] = utc_now()


def broadcast_worker() -> None:
    while True:
        try:
            broadcast_id = BROADCAST_QUEUE.get()
            process_broadcast(broadcast_id)
        except Exception:
            pass
        finally:
            BROADCAST_QUEUE.task_done()


threading.Thread(
    target=broadcast_worker,
    daemon=True,
    name="uzl-broadcast-worker",
).start()


# ============================================================
# BROADCAST API
# ============================================================

@app.get("/api/admin/broadcasts/recipient-count")
@require_permission("broadcast.send")
def recipient_count():
    audience = request.args.get("audience", "ALL_USERS")
    return jsonify({"count": len(eligible_recipients(audience))})


@app.post("/api/admin/broadcasts")
@require_permission("broadcast.send")
def create_broadcast():
    data = request.get_json(silent=True) or {}

    title = str(data.get("title", "")).strip()
    message = str(data.get("message", "")).strip()
    audience = str(data.get("audienceType", "")).strip()

    allowed_audiences = {
        "ALL_USERS",
        "ACTIVE_USERS",
        "SUSPENDED_USERS",
        "USERS_WITH_BOTS",
        "USERS_WITH_RUNNING_BOTS",
        "CUSTOM",
    }

    if not title or not message:
        return jsonify({"error": "Title and message are required"}), 400

    if audience not in allowed_audiences:
        return jsonify({"error": "Invalid audience"}), 400

    if len(title) > 150 or len(message) > 10000:
        return jsonify({"error": "Message too long"}), 400

    broadcast_id = str(uuid.uuid4())

    recipients = (
        eligible_recipients(audience)
        if audience != "CUSTOM"
        else []
    )

    broadcast = {
        "id": broadcast_id,
        "createdBy": request.admin["id"],
        "title": title,
        "message": message,
        "audienceType": audience,
        "status": "QUEUED",
        "createdAt": utc_now(),
        "startedAt": None,
        "completedAt": None,
        "recipientCount": len(recipients),
        "successCount": 0,
        "failureCount": 0,
        "actionButton": data.get("actionButton"),
        "media": data.get("media"),
    }

    BROADCASTS[broadcast_id] = broadcast
    BROADCAST_DELIVERIES[broadcast_id] = []

    audit(
        request.admin["id"],
        "BROADCAST_CREATE",
        metadata={
            "broadcastId": broadcast_id,
            "audience": audience,
            "recipientCount": len(recipients),
        },
    )

    BROADCAST_QUEUE.put(broadcast_id)

    audit(
        request.admin["id"],
        "BROADCAST_SEND",
        metadata={"broadcastId": broadcast_id},
    )

    return jsonify(broadcast), 202


@app.get("/api/admin/broadcasts")
@require_permission("broadcast.send")
def list_broadcasts():
    page = max(1, int(request.args.get("page", "1")))
    limit = min(100, max(1, int(request.args.get("limit", "20"))))

    rows = sorted(
        BROADCASTS.values(),
        key=lambda x: x["createdAt"],
        reverse=True,
    )

    start = (page - 1) * limit

    return jsonify(
        {
            "items": rows[start:start + limit],
            "page": page,
            "limit": limit,
            "total": len(rows),
        }
    )


@app.get("/api/admin/broadcasts/<broadcast_id>")
@require_permission("broadcast.send")
def get_broadcast(broadcast_id: str):
    broadcast = BROADCASTS.get(broadcast_id)

    if not broadcast:
        return jsonify({"error": "Broadcast not found"}), 404

    return jsonify(
        {
            **broadcast,
            "deliveries": BROADCAST_DELIVERIES.get(
                broadcast_id, []
            ),
        }
    )


@app.post("/api/admin/broadcasts/<broadcast_id>/cancel")
@require_permission("broadcast.send")
def cancel_broadcast(broadcast_id: str):
    broadcast = BROADCASTS.get(broadcast_id)

    if not broadcast:
        return jsonify({"error": "Broadcast not found"}), 404

    if broadcast["status"] in {
        "COMPLETED",
        "FAILED",
        "PARTIAL",
        "CANCELLED",
    }:
        return jsonify({"error": "Broadcast cannot be cancelled"}), 409

    broadcast["status"] = "CANCELLED"
    broadcast["completedAt"] = utc_now()

    audit(
        request.admin["id"],
        "BROADCAST_CANCEL",
        metadata={"broadcastId": broadcast_id},
    )

    return jsonify({"ok": True, "status": "CANCELLED"})


# ============================================================
# AUDIT API
# ============================================================

@app.get("/api/admin/audit")
@require_permission("logs.view")
def list_audit():
    search = request.args.get("search", "").lower()
    page = max(1, int(request.args.get("page", "1")))
    limit = min(100, max(1, int(request.args.get("limit", "20"))))

    rows = AUDIT_LOGS

    if search:
        rows = [
            row for row in rows
            if search in json.dumps(
                row,
                default=str,
            ).lower()
        ]

    rows = list(reversed(rows))
    start = (page - 1) * limit

    return jsonify(
        {
            "items": rows[start:start + limit],
            "page": page,
            "limit": limit,
            "total": len(rows),
        }
    )


# ============================================================
# ADMIN PERMISSIONS
# ============================================================

@app.post("/api/admin/settings/permissions")
@require_permission("settings.manage")
def update_permissions():
    data = request.get_json(silent=True) or {}
    permissions = set(data.get("permissions", []))

    if not permissions.issubset(ALL_PERMISSIONS):
        return jsonify({"error": "Invalid permission"}), 400

    # In production this should target a selected admin/role,
    # not blindly modify the caller's permissions.
    target_admin_id = data.get("adminId") or request.admin["id"]

    ADMIN_PERMISSIONS[target_admin_id] = permissions

    audit(
        request.admin["id"],
        "ADMIN_PERMISSION_UPDATE",
        metadata={
            "targetAdminId": target_admin_id,
            "permissionCount": len(permissions),
        },
    )

    return jsonify(
        {
            "ok": True,
            "adminId": target_admin_id,
            "permissions": sorted(permissions),
        }
    )


# ============================================================
# SLASH COMMAND ROUTER
# ============================================================

def execute_admin_command(admin_id: str, command: str) -> dict[str, Any]:
    """
    Framework-independent command parser.

    Connect this function to the existing platform's slash-command
    handler. The platform identity must be passed from trusted
    authentication context, not from message text.
    """
    admin = {
        "id": admin_id,
        "role": (
            "SUPERADMIN"
            if admin_id in SUPERADMIN_IDS
            else "ADMIN"
        ),
        "permissions": (
            ALL_PERMISSIONS
            if admin_id in SUPERADMIN_IDS
            else ADMIN_PERMISSIONS.get(
                admin_id,
                DEFAULT_ADMIN_PERMISSIONS,
            )
        ),
    }

    command = command.strip()
    parts = command.split()
    root = parts[0].lower() if parts else ""

    if root not in {"/admin", "/broadcast"}:
        return {"ok": False, "message": "Unknown command"}

    if root == "/admin":
        if len(parts) == 1:
            return {
                "ok": True,
                "menu": [
                    "users",
                    "bots",
                    "stats",
                    "broadcast",
                    "runners",
                    "deployments",
                    "logs",
                    "settings",
                ],
            }

        section = parts[1].lower()

        permission_map = {
            "users": "users.view",
            "bots": "bots.view",
            "stats": "users.view",
            "broadcast": "broadcast.send",
            "runners": "runners.manage",
            "deployments": "deployments.manage",
            "logs": "logs.view",
            "settings": "settings.manage",
        }

        permission = permission_map.get(section)

        if not permission or not has_permission(admin, permission):
            audit(
                admin_id,
                "COMMAND_PERMISSION_DENIED",
                success=False,
                metadata={"command": "/admin " + section},
            )
            return {
                "ok": False,
                "message": "Permission denied",
            }

        return {
            "ok": True,
            "section": section,
        }

    if root == "/broadcast":
        if not has_permission(admin, "broadcast.send"):
            audit(
                admin_id,
                "COMMAND_PERMISSION_DENIED",
                success=False,
                metadata={"command": "/broadcast"},
            )
            return {
                "ok": False,
                "message": "Permission denied",
            }

        return {
            "ok": True,
            "flow": [
                "AUDIENCE",
                "MESSAGE",
                "PREVIEW",
                "CONFIRM",
                "QUEUE",
                "STATUS",
            ],
        }

    return {"ok": False, "message": "Permission denied"}


# ============================================================
# EXAMPLE HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return jsonify(
        {
            "ok": True,
            "service": "UZL BOT HOST",
            "adminSystem": True,
            "time": utc_now(),
        }
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    BOT_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

    # For production behind Render/reverse proxy, bind to 0.0.0.0
    # and use the PORT supplied by the platform.
    port = int(os.environ.get("PORT", "10000"))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
    )
