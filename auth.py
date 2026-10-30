"""Local password accounts and opaque, expiring HTTP sessions."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from sandbox_executor import SandboxExecutor


class AuthenticationError(ValueError):
    pass


class PermissionDenied(ValueError):
    pass


@dataclass(frozen=True)
class Principal:
    username: str
    role: str


class AuthStore:
    ROLES = {"viewer", "operator", "approver", "admin"}
    SESSION_TTL = 3600

    def __init__(self, path: Path, *, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self.sessions = {}
        self.failures = {}
        self.lock = threading.RLock()

    def _users(self):
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}

    @staticmethod
    def _hash(password, salt):
        return hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()

    def add_user(self, username, password, role):
        import re
        if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_-]{2,40}", username):
            raise ValueError("用户名需为2至40位字母、数字、下划线或连字符")
        if role not in self.ROLES or not isinstance(password, str) or not 12 <= len(password) <= 256:
            raise ValueError("角色无效或密码长度不在12至256字符之间")
        with self.lock:
            users = self._users()
            if username in users:
                raise ValueError("用户已存在，请勿覆盖")
            salt = secrets.token_hex(16)
            users[username] = {"salt": salt, "password_hash": self._hash(password, salt), "role": role, "enabled": True}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            SandboxExecutor._atomic_json_write(self.path, users)

    def principal(self, username):
        user = self._users().get(username)
        if not user or not user.get("enabled") or user.get("role") not in self.ROLES:
            raise AuthenticationError("账号已禁用或不存在")
        return Principal(username, user["role"])

    def login(self, username, password):
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 40 or len(password) > 256:
            raise AuthenticationError("用户名或密码不正确")
        with self.lock:
            now = self.clock()
            attempts = [value for value in self.failures.get(username, []) if value > now - 60]
            if len(attempts) >= 5:
                raise AuthenticationError("登录失败次数过多，请稍后再试")
            user = self._users().get(username)
            salt = user["salt"] if user else "00" * 16
            actual = self._hash(password, salt)
            if not user or not user.get("enabled") or not hmac.compare_digest(actual, user["password_hash"]):
                # Bound rate-limit memory even when arbitrary usernames are submitted.
                if len(self.failures) > 512:
                    self.failures.clear()
                self.failures[username] = [*attempts, now]
                raise AuthenticationError("用户名或密码不正确")
            self.failures.pop(username, None)
            self.sessions = {key: record for key, record in self.sessions.items() if record["expires"] > now}
            if len(self.sessions) >= 256:
                raise AuthenticationError("会话数量已达上限")
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[hashlib.sha256(token.encode()).hexdigest()] = {"username": username, "csrf": csrf, "expires": now + self.SESSION_TTL}
            return token, csrf, self.principal(username)

    def session(self, token, csrf=None, *, write=False):
        if not isinstance(token, str) or not token:
            raise AuthenticationError("请先登录")
        with self.lock:
            record = self.sessions.get(hashlib.sha256(token.encode()).hexdigest())
            if not record or self.clock() >= record["expires"]:
                raise AuthenticationError("会话已失效，请重新登录")
            if write and (not isinstance(csrf, str) or not hmac.compare_digest(csrf, record["csrf"])):
                raise PermissionDenied("请求缺少有效的会话校验")
            return self.principal(record["username"]), record["csrf"]

    def logout(self, token):
        with self.lock:
            self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)
