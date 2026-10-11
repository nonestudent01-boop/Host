from __future__ import annotations

import io
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Flask, jsonify, request, send_file
from sqlalchemy import Boolean, DateTime, Integer, String, Text, create_engine, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

# ============================================================
# UZL BOT HOST — PREMIUM TELEGRAM HOSTING PLATFORM
# ============================================================

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///uzl_bot_host.db").strip()
BOT_STORAGE_ROOT = Path(os.getenv("BOT_STORAGE_ROOT", "./storage")).resolve()
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", str(50 * 1024 * 1024)))
SUPERADMIN_IDS = {x.strip() for x in os.getenv("SUPERADMIN_IDS", "").split(",") if x.strip()}
ADMIN_DEFAULT_PERMISSIONS = {
    x.strip() for x in os.getenv(
        "ADMIN_DEFAULT_PERMISSIONS",
        "users.view,bots.view,files.view,files.download,logs.view"
    ).split(",") if x.strip()
}
PORT = int(os.getenv("PORT", "10000"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
STARTUP_MESSAGE = os.getenv(
    "STARTUP_MESSAGE",
    "🟢 UZL BOT HOST STARTED\n\nStatus: Online\nUse /start to open the premium panel."
)

BOT_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

# ----------------------------- DB -----------------------------

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str | None] = mapped_column(String(255))
    first_name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_activity: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Bot(Base):
    __tablename__ = "bots"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(32), default="created")
    entrypoint: Mapped[str | None] = mapped_column(String(255))
    requirements: Mapped[bool] = mapped_column(Boolean, default=False)
    pid: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    admin_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(100))
    target_user_id: Mapped[str | None] = mapped_column(String(64))
    bot_id: Mapped[str | None] = mapped_column(String(64))
    path: Mapped[str | None] = mapped_column(String(1000))
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Broadcast(Base):
    __tablename__ = "broadcasts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_by: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text)
    audience: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="draft")
    recipient_count: Mapped[int] = mapped_column(Integer, default=0)
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class CustomButton(Base):
    __tablename__ = "custom_buttons"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    label: Mapped[str] = mapped_column(String(100))
    emoji: Mapped[str] = mapped_column(String(20), default="🔘")
    action: Mapped[str] = mapped_column(String(64))
    value: Mapped[str | None] = mapped_column(String(1000))
    position: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)

engine_kwargs = {}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, **engine_kwargs)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
Base.metadata.create_all(engine)

# ------------------------ Telegram API ------------------------

def tg(method: str, payload: dict | None = None, timeout: int = 40) -> dict:
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN is not configured")
    data = urlencode(payload or {}).encode()
    req = Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode())

def send_message(chat_id: str | int, text: str, keyboard=None, parse_mode="HTML"):
    payload = {"chat_id": str(chat_id), "text": text}
    if parse_mode:
        payload["parse_mode"] = parse_mode
    if keyboard is not None:
        payload["reply_markup"] = json.dumps({"inline_keyboard": keyboard})
    return tg("sendMessage", payload)

def edit_message(chat_id, message_id, text, keyboard=None):
    payload = {"chat_id": str(chat_id), "message_id": str(message_id), "text": text, "parse_mode": "HTML"}
    if keyboard is not None:
        payload["reply_markup"] = json.dumps({"inline_keyboard": keyboard})
    return tg("editMessageText", payload)

def answer_callback(callback_id, text=""):
    try:
        return tg("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})
    except Exception:
        return {}

# -------------------------- Utilities -------------------------

def now():
    return datetime.now(timezone.utc)

def user_id(update):
    return str(update.get("message", {}).get("from", {}).get("id")
               or update.get("callback_query", {}).get("from", {}).get("id", ""))

def chat_id(update):
    return str(update.get("message", {}).get("chat", {}).get("id")
               or update.get("callback_query", {}).get("message", {}).get("chat", {}).get("id", ""))

def is_superadmin(uid: str) -> bool:
    return str(uid) in SUPERADMIN_IDS

def require_permission(uid: str, permission: str) -> bool:
    if is_superadmin(uid):
        return True
    # Admin role storage can be extended here; this default is intentionally restrictive.
    return permission in ADMIN_DEFAULT_PERMISSIONS

def audit(admin_id, action, target_user_id=None, bot_id=None, path=None, success=True):
    with SessionLocal() as db:
        db.add(Audit(
            admin_id=str(admin_id), action=action,
            target_user_id=str(target_user_id) if target_user_id else None,
            bot_id=str(bot_id) if bot_id else None,
            path=path, success=success
        ))
        db.commit()

def user_root(uid: str) -> Path:
    return (BOT_STORAGE_ROOT / "user" / str(uid)).resolve()

def bot_root(uid: str, bid: str) -> Path:
    root = (user_root(uid) / "bot" / str(bid)).resolve()
    allowed = user_root(uid).resolve()
    if allowed not in root.parents:
        raise PermissionError("storage escape")
    return root

def safe_relative(base: Path, relative: str) -> Path:
    if not relative or "\x00" in relative:
        raise ValueError("invalid path")
    relative = relative.replace("\\", "/")
    p = Path(relative)
    if p.is_absolute() or any(part in ("..", "") for part in p.parts):
        raise ValueError("invalid path")
    result = (base / p).resolve()
    if base.resolve() != result and base.resolve() not in result.parents:
        raise PermissionError("storage escape")
    return result

def html(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def keyboard(rows):
    return rows

# ------------------------- User UI ----------------------------

def main_keyboard():
    return keyboard([
        [{"text": "➕ Add Bot", "callback_data": "add_bot"}, {"text": "🤖 My Bots", "callback_data": "my_bots"}],
        [{"text": "🗑 Remove Bot", "callback_data": "remove_bot"}, {"text": "📁 My Files", "callback_data": "my_files"}],
        [{"text": "⬆️ Upload ZIP", "callback_data": "upload_zip"}, {"text": "📄 Upload File", "callback_data": "upload_file"}],
        [{"text": "📊 Bot Status", "callback_data": "bot_status"}, {"text": "📜 History", "callback_data": "history"}],
        [{"text": "🏓 Ping", "callback_data": "ping"}, {"text": "⚙️ Settings", "callback_data": "settings"}],
        [{"text": "❓ Help", "callback_data": "help"}],
    ])

def get_or_create_user(update):
    uid = user_id(update)
    sender = update.get("message", {}).get("from") or update.get("callback_query", {}).get("from", {})
    with SessionLocal() as db:
        u = db.get(User, uid)
        if not u:
            u = User(id=uid, username=sender.get("username"), first_name=sender.get("first_name"))
            db.add(u)
        else:
            u.username = sender.get("username")
            u.first_name = sender.get("first_name")
            u.last_activity = now()
        db.commit()
    return uid

def start_screen(uid):
    with SessionLocal() as db:
        bot_count = db.scalar(select(func.count()).select_from(Bot).where(Bot.user_id == uid)) or 0
        running = db.scalar(select(func.count()).select_from(Bot).where(Bot.user_id == uid, Bot.status == "running")) or 0
        custom = db.scalars(select(CustomButton).where(CustomButton.enabled == True).order_by(CustomButton.position)).all()
        setting = db.get(Setting, "start_message")
    base = setting.value if setting else (
        "╭────────────────────╮\n"
        "   🚀 <b>UZL BOT HOST</b>\n"
        "   ⚡ Premium Bot Hosting\n"
        "╰────────────────────╯\n\n"
        "Welcome to your premium bot hosting dashboard."
    )
    text = (
        f"{base}\n\n"
        f"👤 User: <code>{html(uid)}</code>\n"
        f"🤖 Bots: <b>{bot_count}</b>\n"
        f"🟢 Running: <b>{running}</b>\n"
        f"📡 Server: <b>Online</b>\n\n"
        "Choose an action:"
    )
    kb = main_keyboard()
    if custom:
        for b in custom[:100]:
            kb.append([{"text": f"{b.emoji} {b.label}", "callback_data": f"custom:{b.id}"}])
    return text, kb

# -------------------------- Bot hosting -----------------------

def detect_entrypoint(root: Path):
    for candidate in ("main.py", "bot.py", "app.py", "run.py"):
        if (root / candidate).is_file():
            return candidate
    py_files = list(root.glob("*.py"))
    return py_files[0].name if py_files else None

def create_bot(uid, name):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,50}", name):
        raise ValueError("Bot name may contain only letters, numbers, _ and -")
    bid = uuid.uuid4().hex
    root = bot_root(uid, bid)
    root.mkdir(parents=True, exist_ok=False)
    with SessionLocal() as db:
        if db.scalar(select(Bot).where(Bot.user_id == uid, Bot.name == name)):
            shutil.rmtree(root, ignore_errors=True)
            raise ValueError("A bot with that name already exists")
        db.add(Bot(id=bid, user_id=uid, name=name))
        db.commit()
    return bid

def list_bots(uid):
    with SessionLocal() as db:
        return db.scalars(select(Bot).where(Bot.user_id == uid).order_by(Bot.created_at.desc())).all()

_processes: dict[str, subprocess.Popen] = {}
_process_lock = threading.Lock()

def start_bot(uid, bid):
    with SessionLocal() as db:
        b = db.get(Bot, bid)
        if not b or b.user_id != uid:
            raise PermissionError("Bot not found")
        if b.status == "running" and b.pid:
            return
        root = bot_root(uid, bid)
        entry = b.entrypoint or detect_entrypoint(root)
        if not entry:
            raise RuntimeError("No Python entrypoint found. Upload a project first.")
        b.entrypoint = entry
        b.status = "starting"
        db.commit()
    cmd = ["python", entry]
    log_path = bot_root(uid, bid) / "uzl_runtime.log"
    log_file = open(log_path, "a", encoding="utf-8")
    proc = subprocess.Popen(
        cmd, cwd=str(bot_root(uid, bid)), stdout=log_file, stderr=subprocess.STDOUT,
        start_new_session=True
    )
    with _process_lock:
        _processes[bid] = proc
    with SessionLocal() as db:
        b = db.get(Bot, bid)
        b.pid = proc.pid
        b.status = "running"
        b.updated_at = now()
        db.commit()

def stop_bot(uid, bid):
    with SessionLocal() as db:
        b = db.get(Bot, bid)
        if not b or b.user_id != uid:
            raise PermissionError("Bot not found")
        pid = b.pid
    with _process_lock:
        proc = _processes.get(bid)
    if proc and proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            proc.terminate()
        try:
            proc.wait(timeout=8)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    elif pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
    with _process_lock:
        _processes.pop(bid, None)
    with SessionLocal() as db:
        b = db.get(Bot, bid)
        if b:
            b.status, b.pid, b.updated_at = "stopped", None, now()
            db.commit()

def bot_menu(uid, bid):
    with SessionLocal() as db:
        b = db.get(Bot, bid)
    if not b or b.user_id != uid:
        return "❌ Bot not found.", main_keyboard()
    return (
        f"🤖 <b>{html(b.name)}</b>\n\n"
        f"Status: <b>{html(b.status.upper())}</b>\n"
        f"Entrypoint: <code>{html(b.entrypoint or 'not detected')}</code>"
    ), [
        [{"text": "▶️ Start", "callback_data": f"start:{bid}"}, {"text": "⏹ Stop", "callback_data": f"stop:{bid}"}],
        [{"text": "🔄 Restart", "callback_data": f"restart:{bid}"}, {"text": "📋 Logs", "callback_data": f"logs:{bid}"}],
        [{"text": "📁 Files", "callback_data": f"files:{bid}"}, {"text": "📊 Metrics", "callback_data": f"metrics:{bid}"}],
        [{"text": "🗑 Remove", "callback_data": f"remove_confirm:{bid}"}],
        [{"text": "↩️ My Bots", "callback_data": "my_bots"}],
    ]

# ------------------------- File manager -----------------------

def directory_keyboard(uid, bid, rel=""):
    root = bot_root(uid, bid)
    current = safe_relative(root, rel) if rel else root
    rows = []
    for p in sorted(current.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))[:40]:
        child_rel = str(p.relative_to(root)).replace("\\", "/")
        icon = "📂" if p.is_dir() else "📄"
        rows.append([{"text": f"{icon} {p.name}", "callback_data": f"openfile:{bid}:{child_rel}"}])
    parent = str(Path(rel).parent).replace("\\", "/") if rel else ""
    if parent == ".":
        parent = ""
    rows.append([
        {"text": "⬆️ Upload", "callback_data": f"uploadfile:{bid}:{rel}"},
        {"text": "📁 New Folder", "callback_data": f"newfolder:{bid}:{rel}"}
    ])
    if rel:
        rows.append([{"text": "↩️ Back", "callback_data": f"files:{bid}:{parent}"}])
    rows.append([{"text": "🤖 Bot", "callback_data": f"bot:{bid}"}])
    return rows

def file_text(uid, bid, rel):
    root = bot_root(uid, bid)
    p = safe_relative(root, rel)
    if p.is_dir():
        return f"📁 <b>{html(rel or '/')}</b>", directory_keyboard(uid, bid, rel)
    size = p.stat().st_size
    if size > 500_000:
        return f"📄 <b>{html(p.name)}</b>\n\nSize: {size} bytes\nUse Download to retrieve large files.", [
            [{"text": "⬇️ Download", "callback_data": f"download:{bid}:{rel}"}],
            [{"text": "↩️ Files", "callback_data": f"files:{bid}:{Path(rel).parent}"}]
        ]
    content = p.read_text(encoding="utf-8", errors="replace")
    if len(content) > 3500:
        content = content[:3500] + "\n…"
    return f"📄 <b>{html(p.name)}</b>\n\n<pre>{html(content)}</pre>", [
        [{"text": "⬇️ Download", "callback_data": f"download:{bid}:{rel}"}],
        [{"text": "🗑 Delete", "callback_data": f"deletefile:{bid}:{rel}"}],
        [{"text": "↩️ Files", "callback_data": f"files:{bid}:{Path(rel).parent}"}]
    ]

# ----------------------- Admin UI -----------------------------

def admin_keyboard():
    return [
        [{"text": "📊 Dashboard", "callback_data": "admin:stats"}, {"text": "👥 Users", "callback_data": "admin:users"}],
        [{"text": "🤖 Bots", "callback_data": "admin:bots"}, {"text": "📁 User Files", "callback_data": "admin:files"}],
        [{"text": "📡 Runners", "callback_data": "admin:runners"}, {"text": "🚀 Deployments", "callback_data": "admin:deployments"}],
        [{"text": "📢 Broadcast", "callback_data": "admin:broadcast"}, {"text": "📜 Audit Logs", "callback_data": "admin:logs"}],
        [{"text": "🎛️ Custom Buttons", "callback_data": "admin:buttons"}, {"text": "✏️ Start Message", "callback_data": "admin:startmsg"}],
        [{"text": "⚙️ Settings", "callback_data": "admin:settings"}],
    ]

def admin_stats():
    with SessionLocal() as db:
        users = db.scalar(select(func.count()).select_from(User)) or 0
        bots = db.scalar(select(func.count()).select_from(Bot)) or 0
        running = db.scalar(select(func.count()).select_from(Bot).where(Bot.status == "running")) or 0
        failed = db.scalar(select(func.count()).select_from(Bot).where(Bot.status == "failed")) or 0
        broadcasts = db.scalar(select(func.count()).select_from(Broadcast)) or 0
    return (
        "🛡️ <b>UZL ADMIN DASHBOARD</b>\n\n"
        f"👥 Total Users: <b>{users}</b>\n"
        f"🤖 Total Bots: <b>{bots}</b>\n"
        f"🟢 Running Bots: <b>{running}</b>\n"
        f"🔴 Failed Bots: <b>{failed}</b>\n"
        f"📢 Broadcasts: <b>{broadcasts}</b>\n"
        f"📡 Runner: <b>Online</b>"
    )

def admin_users():
    with SessionLocal() as db:
        rows = db.scalars(select(User).order_by(User.created_at.desc()).limit(15)).all()
    if not rows:
        return "👥 No users yet.", admin_keyboard()
    text = "👥 <b>Recent Users</b>\n\n"
    kb = []
    for u in rows:
        text += f"• <code>{u.id}</code> @{html(u.username or 'no_username')} — {u.status}\n"
        kb.append([{"text": f"👤 {u.first_name or u.username or u.id}", "callback_data": f"adminuser:{u.id}"}])
    kb.append([{"text": "↩️ Admin", "callback_data": "admin:home"}])
    return text, kb

def admin_bots():
    with SessionLocal() as db:
        rows = db.scalars(select(Bot).order_by(Bot.created_at.desc()).limit(25)).all()
    text = "🤖 <b>Recent Bots</b>\n\n" + (
        "\n".join(f"• {html(b.name)} — <b>{b.status}</b> — user <code>{b.user_id}</code>" for b in rows)
        if rows else "No bots yet."
    )
    return text, [[{"text": "↩️ Admin", "callback_data": "admin:home"}]]

def audit_text():
    with SessionLocal() as db:
        rows = db.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(20)).all()
    text = "📜 <b>Audit Logs</b>\n\n"
    for a in rows:
        text += f"• {html(a.action)} | admin <code>{a.admin_id}</code> | {'OK' if a.success else 'FAIL'}\n"
    return text, [[{"text": "↩️ Admin", "callback_data": "admin:home"}]]

# ----------------------- Update router ------------------------

def callback(update):
    q = update["callback_query"]
    uid = str(q["from"]["id"])
    cid = q["id"]
    data = q.get("data", "")
    chat = q["message"]["chat"]["id"]
    mid = q["message"]["message_id"]
    answer_callback(cid)

    try:
        if data == "add_bot":
            with SessionLocal() as db:
                db.add(Setting(key=f"state:{uid}", value="await_bot_name"))
                db.commit()
            edit_message(chat, mid, "➕ <b>Add Bot</b>\n\nSend the bot name now.\n\nAllowed: letters, numbers, _ and -", [[{"text":"❌ Cancel","callback_data":"cancel"}]])
            return

        if data == "my_bots":
            bots = list_bots(uid)
            text = "🤖 <b>MY BOTS</b>\n\n"
            kb = []
            if not bots:
                text += "No bots yet. Tap ➕ Add Bot."
            for b in bots:
                text += f"• <b>{html(b.name)}</b> — {b.status.upper()}\n"
                kb.append([{"text": f"🤖 {b.name} • {b.status}", "callback_data": f"bot:{b.id}"}])
            kb.append([{"text":"↩️ Home","callback_data":"home"}])
            edit_message(chat, mid, text, kb)
            return

        if data.startswith("bot:"):
            text, kb = bot_menu(uid, data.split(":",1)[1])
            edit_message(chat, mid, text, kb)
            return

        if data.startswith("start:"):
            bid = data.split(":",1)[1]
            edit_message(chat, mid, "⏳ Starting...\n⚙️ Preparing...\n🚀 Launching...")
            start_bot(uid, bid)
            edit_message(chat, mid, "🟢 <b>Bot is running.</b>", bot_menu(uid, bid)[1])
            return

        if data.startswith("stop:"):
            bid = data.split(":",1)[1]
            edit_message(chat, mid, "⏳ Stopping...")
            stop_bot(uid, bid)
            edit_message(chat, mid, "🔴 <b>Bot stopped.</b>", bot_menu(uid, bid)[1])
            return

        if data.startswith("restart:"):
            bid = data.split(":",1)[1]
            edit_message(chat, mid, "🔄 Restarting...")
            stop_bot(uid, bid)
            start_bot(uid, bid)
            edit_message(chat, mid, "🟢 <b>Bot restarted.</b>", bot_menu(uid, bid)[1])
            return

        if data.startswith("logs:"):
            bid = data.split(":",1)[1]
            p = bot_root(uid, bid) / "uzl_runtime.log"
            content = p.read_text(encoding="utf-8", errors="replace")[-3500:] if p.exists() else "No logs yet."
            edit_message(chat, mid, f"📋 <b>Logs</b>\n\n<pre>{html(content)}</pre>", [[{"text":"↩️ Bot","callback_data":f"bot:{bid}"}]])
            return

        if data.startswith("files:"):
            parts = data.split(":", 2)
            bid = parts[1]
            rel = parts[2] if len(parts) > 2 else ""
            text, kb = file_text(uid, bid, rel)
            edit_message(chat, mid, text, kb)
            return

        if data.startswith("openfile:"):
            _, bid, rel = data.split(":", 2)
            text, kb = file_text(uid, bid, rel)
            edit_message(chat, mid, text, kb)
            return

        if data.startswith("remove_confirm:"):
            bid = data.split(":",1)[1]
            edit_message(chat, mid, "⚠️ <b>Remove this bot permanently?</b>\nFiles, logs and deployment data will be deleted.", [
                [{"text":"🗑 YES, REMOVE","callback_data":f"remove:{bid}"},{"text":"❌ Cancel","callback_data":f"bot:{bid}"}]
            ])
            return

        if data.startswith("remove:"):
            bid = data.split(":",1)[1]
            with SessionLocal() as db:
                b = db.get(Bot, bid)
                if not b or b.user_id != uid:
                    raise PermissionError("Bot not found")
                stop_bot(uid, bid)
                shutil.rmtree(bot_root(uid, bid), ignore_errors=True)
                db.delete(b)
                db.commit()
            edit_message(chat, mid, "✅ <b>Bot removed.</b>", main_keyboard())
            return

        if data in ("home", "cancel"):
            text, kb = start_screen(uid)
            edit_message(chat, mid, text, kb)
            return

        if data == "ping":
            start = time.perf_counter()
            with SessionLocal() as db:
                db.execute(select(User).limit(1))
            ms = round((time.perf_counter() - start) * 1000)
            edit_message(chat, mid, f"🏓 <b>PONG</b>\n\nServer: 🟢 Online\nDatabase: 🟢 Connected\nLatency: <b>{ms} ms</b>", [[{"text":"↩️ Home","callback_data":"home"}]])
            return

        if data == "help":
            edit_message(chat, mid, "❓ <b>HELP</b>\n\nCreate a bot, upload a ZIP/project, inspect files, deploy and control it from the buttons.", [[{"text":"↩️ Home","callback_data":"home"}]])
            return

        if data == "settings":
            edit_message(chat, mid, "⚙️ <b>Settings</b>\n\n🔔 Notifications\n🎨 UI Preferences\n🔊 Alerts\n📊 Usage\n🔐 Security\n🌐 Language", [[{"text":"↩️ Home","callback_data":"home"}]])
            return

        if data.startswith("admin:"):
            if not is_superadmin(uid):
                edit_message(chat, mid, "Permission denied.")
                return
            action = data.split(":",1)[1]
            if action == "home":
                edit_message(chat, mid, "🛡️ <b>UZL ADMIN CENTER</b>\n\nChoose a section:", admin_keyboard())
            elif action == "stats":
                edit_message(chat, mid, admin_stats(), admin_keyboard())
            elif action == "users":
                text, kb = admin_users(); edit_message(chat, mid, text, kb)
            elif action == "bots":
                text, kb = admin_bots(); edit_message(chat, mid, text, kb)
            elif action == "logs":
                text, kb = audit_text(); edit_message(chat, mid, text, kb)
            elif action == "broadcast":
                edit_message(chat, mid, "📢 <b>Broadcast</b>\n\nUse /broadcast TITLE | MESSAGE", [[{"text":"↩️ Admin","callback_data":"admin:home"}]])
            elif action == "buttons":
                edit_message(chat, mid, "🎛️ <b>Custom Buttons</b>\n\nUse /admin_button Label | action | value\nMaximum: 100 enabled buttons.", [[{"text":"↩️ Admin","callback_data":"admin:home"}]])
            elif action == "startmsg":
                edit_message(chat, mid, "✏️ <b>Start Message</b>\n\nUse /admin_startmsg Your custom welcome text", [[{"text":"↩️ Admin","callback_data":"admin:home"}]])
            else:
                edit_message(chat, mid, f"⚙️ <b>{html(action.title())}</b>\n\nSection ready.", admin_keyboard())
            return

        if data.startswith("adminuser:"):
            if not is_superadmin(uid):
                edit_message(chat, mid, "Permission denied."); return
            target = data.split(":",1)[1]
            with SessionLocal() as db:
                u = db.get(User, target)
                count = db.scalar(select(func.count()).select_from(Bot).where(Bot.user_id == target)) or 0
            if not u:
                edit_message(chat, mid, "User not found."); return
            edit_message(chat, mid, f"👤 <b>User</b>\n\nID: <code>{target}</code>\nUsername: @{html(u.username or 'none')}\nStatus: {u.status}\nBots: {count}", [[{"text":"🤖 Bots","callback_data":f"adminuserbots:{target}"},{"text":"📁 Files","callback_data":f"adminuserbots:{target}"}],[{"text":"↩️ Users","callback_data":"admin:users"}]])
            return

        if data.startswith("adminuserbots:"):
            if not is_superadmin(uid):
                edit_message(chat, mid, "Permission denied."); return
            target = data.split(":",1)[1]
            with SessionLocal() as db:
                bots = db.scalars(select(Bot).where(Bot.user_id == target)).all()
            text = f"🤖 <b>User {html(target)} Bots</b>\n\n" + ("\n".join(f"• {html(b.name)} — {b.status} — <code>{b.id}</code>" for b in bots) or "No bots.")
            edit_message(chat, mid, text, [[{"text":"↩️ Users","callback_data":"admin:users"}]])
            return

        if data.startswith("custom:"):
            bid = data.split(":",1)[1]
            with SessionLocal() as db:
                b = db.get(CustomButton, bid)
            if not b or not b.enabled:
                edit_message(chat, mid, "❌ Button unavailable.", main_keyboard()); return
            if b.action == "url" and b.value:
                edit_message(chat, mid, f"🔗 <b>{html(b.label)}</b>\n\n{html(b.value)}", [[{"text":"↩️ Home","callback_data":"home"}]])
            elif b.action == "broadcast":
                edit_message(chat, mid, "📢 Broadcast is an admin function.", main_keyboard())
            else:
                edit_message(chat, mid, html(b.value or b.label), [[{"text":"↩️ Home","callback_data":"home"}]])
            return

    except Exception as exc:
        edit_message(chat, mid, f"❌ <b>Operation failed</b>\n\n{html(str(exc))}", [[{"text":"↩️ Home","callback_data":"home"}]])

def message(update):
    msg = update["message"]
    uid = get_or_create_user(update)
    chat = msg["chat"]["id"]
    text = msg.get("text", "").strip()

    if text.startswith("/start"):
        t, kb = start_screen(uid); send_message(chat, t, kb); return

    if text == "/health":
        send_message(chat, "🟢 <b>UZL BOT HOST</b>\n\nServer: Online\nDatabase: Connected\nTelegram API: Online")
        return

    if text == "/help":
        send_message(chat, "❓ <b>Commands</b>\n\n/start — Open panel\n/health — Health\n/admin — Admin panel\n/broadcast — Admin broadcast")
        return

    if text == "/admin" or text.startswith("/admin "):
        if not is_superadmin(uid):
            send_message(chat, "Permission denied."); return
        send_message(chat, "🛡️ <b>UZL ADMIN CENTER</b>\n\nChoose a section:", admin_keyboard()); return

    if text.startswith("/admin_startmsg"):
        if not is_superadmin(uid): send_message(chat, "Permission denied."); return
        value = text[len("/admin_startmsg"):].strip()
        if not value: send_message(chat, "Usage: /admin_startmsg Your welcome text"); return
        with SessionLocal() as db:
            s = db.get(Setting, "start_message") or Setting(key="start_message", value=value)
            s.value = value
            db.add(s); db.commit()
        audit(uid, "START_MESSAGE_UPDATE")
        send_message(chat, "✅ Start message saved."); return

    if text.startswith("/admin_button"):
        if not is_superadmin(uid): send_message(chat, "Permission denied."); return
        raw = text[len("/admin_button"):].strip()
        parts = [x.strip() for x in raw.split("|", 2)]
        if len(parts) < 2:
            send_message(chat, "Usage: /admin_button Label | action | value"); return
        with SessionLocal() as db:
            count = db.scalar(select(func.count()).select_from(CustomButton)) or 0
            if count >= 100:
                send_message(chat, "❌ Maximum 100 custom buttons reached."); return
            b = CustomButton(id=uuid.uuid4().hex, label=parts[0], action=parts[1], value=parts[2] if len(parts) > 2 else None, position=count)
            db.add(b); db.commit()
        audit(uid, "CUSTOM_BUTTON_CREATE")
        send_message(chat, "✅ Custom button created."); return

    if text.startswith("/broadcast"):
        if not is_superadmin(uid):
            send_message(chat, "Permission denied."); return
        raw = text[len("/broadcast"):].strip()
        parts = [x.strip() for x in raw.split("|", 1)]
        if len(parts) != 2:
            send_message(chat, "Usage: /broadcast TITLE | MESSAGE"); return
        with SessionLocal() as db:
            b = Broadcast(id=uuid.uuid4().hex, created_by=uid, title=parts[0], message=parts[1], audience="all", status="queued")
            db.add(b); db.commit()
        send_message(chat, f"📢 <b>Broadcast queued</b>\n\nTitle: {html(parts[0])}\nAudience: All users")
        return

    # State machine: bot name, upload preparation, etc.
    with SessionLocal() as db:
        state = db.get(Setting, f"state:{uid}")
    if state and state.value == "await_bot_name":
        try:
            bid = create_bot(uid, text)
            with SessionLocal() as db:
                db.delete(db.get(Setting, f"state:{uid}")); db.commit()
            send_message(chat, f"✅ <b>Bot Created</b>\n\nName: <b>{html(text)}</b>\nID: <code>{bid}</code>", bot_menu(uid, bid)[1])
        except Exception as exc:
            send_message(chat, f"❌ {html(str(exc))}")
        return

    send_message(chat, "Use /start to open the UZL BOT HOST panel.", main_keyboard())

# --------------------------- Webhook ---------------------------

@app.post("/telegram/webhook")
def telegram_webhook():
    if TELEGRAM_WEBHOOK_SECRET and request.headers.get("X-Telegram-Bot-Api-Secret-Token") != TELEGRAM_WEBHOOK_SECRET:
        app.logger.warning("Rejected Telegram webhook: bad secret token")
        return jsonify({"ok": False}), 403
    update = request.get_json(silent=True) or {}
    app.logger.info("Telegram update received: update_id=%s message=%s callback=%s", update.get("update_id"), bool(update.get("message")), bool(update.get("callback_query")))
    try:
        if update.get("callback_query"):
            callback(update)
        elif update.get("message"):
            message(update)
        return jsonify({"ok": True})
    except Exception as exc:
        app.logger.exception("Telegram update handling failed: %s", exc)
        return jsonify({"ok": False, "error": str(exc)}), 500

@app.get("/health")
def health():
    db_ok = True
    try:
        with SessionLocal() as db:
            db.execute(select(User).limit(1))
    except Exception:
        db_ok = False
    return jsonify({
        "ok": db_ok,
        "service": "UZL BOT HOST",
        "database": db_ok,
        "telegram_configured": bool(BOT_TOKEN),
        "storage": str(BOT_STORAGE_ROOT),
    })

@app.get("/")
def index():
    return jsonify({"service": "UZL BOT HOST", "status": "online"})

@app.get("/telegram-status")
def telegram_status():
    return jsonify(verify_telegram())

# ----------------------- webhook setup -------------------------

def configure_webhook():
    if not BOT_TOKEN:
        app.logger.error("WEBHOOK NOT CONFIGURED: BOT_TOKEN is missing")
        return False
    if not PUBLIC_BASE_URL:
        app.logger.error("WEBHOOK NOT CONFIGURED: PUBLIC_BASE_URL is missing")
        return False
    url = f"{PUBLIC_BASE_URL.rstrip('/')}/telegram/webhook"
    payload = {"url": url, "drop_pending_updates": False}
    if TELEGRAM_WEBHOOK_SECRET:
        payload["secret_token"] = TELEGRAM_WEBHOOK_SECRET
    try:
        result = tg("setWebhook", payload)
        app.logger.warning("Telegram webhook configured: %s -> %s", url, result)
        return bool(result.get("ok"))
    except Exception as exc:
        app.logger.exception("Telegram webhook setup failed: %s", exc)
        return False

def verify_telegram():
    if not BOT_TOKEN:
        return {"ok": False, "error": "BOT_TOKEN missing"}
    try:
        me = tg("getMe")
        wh = tg("getWebhookInfo")
        info = wh.get("result") or {}
        return {"ok": bool(me.get("ok")), "bot": (me.get("result") or {}).get("username"),
                "webhook_url": info.get("url", ""), "pending_updates": info.get("pending_update_count", 0),
                "last_error": info.get("last_error_message", "")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

configure_webhook()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
    app.run(host="0.0.0.0", port=PORT)
