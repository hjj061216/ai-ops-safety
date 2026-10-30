"""Backend-only settings and bounded Chat Completions transports."""
from __future__ import annotations

import json
import math
import os
import re
from http.client import HTTPException, IncompleteRead
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent
CONFIG_KEYS = {"LLM_PROVIDER", "DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL",
               "LLM_TIMEOUT_SECONDS", "LLM_MAX_TOKENS", "OLLAMA_MODEL", "OLLAMA_URL",
               "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL", "LLM_JSON_MODE", "LLM_TOKEN_LIMIT_PARAM"}


class ModelUnavailableError(RuntimeError):
    """Transport/configuration failure; contains no remote response or secret."""


class ModelOutputError(ValueError):
    """Untrusted output must never trigger an availability fallback."""


def _read_env(path):
    if not path.is_file():
        return {}
    settings = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, value = line.partition("=")
        name = name.strip()
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            raise ModelUnavailableError(".env 配置格式不正确；每行应为变量名=值。")
        if name not in CONFIG_KEYS:
            continue
        value = value.strip()
        if value.startswith(('"', "'")):
            if len(value) < 2 or value[-1] != value[0]:
                raise ModelUnavailableError(".env 配置中的引号未闭合。")
            value = value[1:-1]
        settings[name] = value
    return settings


@dataclass(frozen=True)
class ModelSettings:
    provider: str
    model: str
    api_key: str = field(default="", repr=False)
    base_url: str = "https://api.deepseek.com"
    timeout: float = 30
    max_tokens: int = 4096
    ollama_url: str = "http://127.0.0.1:11434/api/chat"
    json_mode: str = "json_object"
    token_limit_param: str = "max_tokens"

    @property
    def provider_label(self):
        return {"deepseek":"DeepSeek API", "openai_compatible":"兼容 API", "ollama":"本地 Ollama"}[self.provider]

    def public_config(self):
        try:
            host = urlsplit(self.ollama_url if self.provider == 'ollama' else self.base_url).hostname or ''
        except ValueError:
            host = ''
        safe = lambda value: value.replace(self.api_key, '[已隐藏]') if self.api_key else value
        return {'provider':self.provider, 'provider_label':self.provider_label, 'model':safe(self.model),
                'endpoint_host':safe(host),
                'api_key_configured':bool(self.api_key) if self.provider != 'ollama' else None}

    @classmethod
    def load(cls, *, env_file=None, environ=None, provider=None, model=None, ollama_url=None):
        values = _read_env(Path(env_file) if env_file is not None else ROOT / ".env")
        environment = os.environ if environ is None else environ
        values.update({name:environment[name] for name in CONFIG_KEYS if name in environment})
        selected = (provider or values.get("LLM_PROVIDER", "deepseek")).strip().lower()
        if selected not in {"deepseek", "openai_compatible", "ollama"}:
            raise ModelUnavailableError("LLM_PROVIDER 只能是 deepseek、openai_compatible 或 ollama。")
        model_setting = {'deepseek':'DEEPSEEK_MODEL', 'openai_compatible':'LLM_MODEL', 'ollama':'OLLAMA_MODEL'}[selected]
        name = model or values.get(model_setting, {'deepseek':'deepseek-flash','ollama':'qwen2.5:3b'}.get(selected, ''))
        if not isinstance(name, str) or not name.strip() or len(name) > 256:
            raise ModelUnavailableError(f"{model_setting} 模型名称配置无效或未填写。")
        base_setting = 'LLM_BASE_URL' if selected == 'openai_compatible' else 'DEEPSEEK_BASE_URL'
        base = (values.get(base_setting, '' if selected == 'openai_compatible' else 'https://api.deepseek.com')
                if selected != 'ollama' else 'https://api.deepseek.com').strip().rstrip('/')
        if selected == 'openai_compatible' and base.endswith('/chat/completions'):
            base = base[:-len('/chat/completions')]
        try:
            url = urlsplit(base)
            valid_url = (url.scheme == 'https' and bool(url.hostname) and (url.port is None or 1 <= url.port <= 65535)
                         and url.username is None and url.password is None and not url.query and not url.fragment
                         and not any(ord(char) <= 32 or ord(char) == 127 for char in base)
                         and '%' not in url.netloc and '\\' not in base)
        except ValueError:
            valid_url = False
        if selected == 'deepseek' and not (valid_url and url.hostname == 'api.deepseek.com'
                                          and url.port in {None,443} and url.path in {'','/v1'}):
            raise ModelUnavailableError("DEEPSEEK_BASE_URL 必须是官方 HTTPS 地址 https://api.deepseek.com（可带 /v1）。")
        if selected == 'openai_compatible' and not valid_url:
            raise ModelUnavailableError('LLM_BASE_URL 必须是有效 HTTPS 地址，且不能含凭据、查询参数或片段。')
        try:
            timeout = float(values.get("LLM_TIMEOUT_SECONDS", "30"))
            tokens = int(values.get("LLM_MAX_TOKENS", "4096"))
            if not math.isfinite(timeout) or not 1 <= timeout <= 120 or not 1 <= tokens <= 16384:
                raise ValueError()
        except (ValueError, TypeError, OverflowError):
            raise ModelUnavailableError("模型超时需为1至120秒，输出上限需为1至16384个 token。") from None
        key_setting = 'LLM_API_KEY' if selected == 'openai_compatible' else 'DEEPSEEK_API_KEY'
        key = values.get(key_setting, '').strip() if selected != 'ollama' else ''
        if any(ord(char) <= 32 or ord(char) == 127 for char in key):
            raise ModelUnavailableError(f'{key_setting} 格式无效。')
        json_mode = values.get('LLM_JSON_MODE', 'json_object') if selected == 'openai_compatible' else 'json_object'
        token_param = values.get('LLM_TOKEN_LIMIT_PARAM', 'max_tokens') if selected == 'openai_compatible' else 'max_tokens'
        if json_mode not in {'json_object','prompt_only'}:
            raise ModelUnavailableError('LLM_JSON_MODE 只能为 json_object 或 prompt_only。')
        if token_param not in {'max_tokens','max_completion_tokens'}:
            raise ModelUnavailableError('LLM_TOKEN_LIMIT_PARAM 只能为 max_tokens 或 max_completion_tokens。')
        local_url = 'http://127.0.0.1:11434/api/chat'
        if selected == 'ollama':
            local_url = ollama_url or values.get('OLLAMA_URL', local_url)
            try:
                local = urlsplit(local_url)
                valid_local = (local.scheme in {'http','https'} and bool(local.hostname)
                               and (local.port is None or 1 <= local.port <= 65535)
                               and local.username is None and local.password is None
                               and not local.query and not local.fragment
                               and not any(ord(char) <= 32 or ord(char) == 127 for char in local_url)
                               and '%' not in local.netloc and '\\' not in local_url)
            except ValueError:
                valid_local = False
            if not valid_local:
                raise ModelUnavailableError('OLLAMA_URL 必须是有效 HTTP/HTTPS 服务地址，不能含凭据、查询参数或片段。')
        return cls(selected, name.strip(), key, base, timeout, tokens,
                   local_url, json_mode, token_param)


class NoModelRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ChatCompletionsClient:
    MAX_RESPONSE_BYTES = 1024 * 1024

    def __init__(self, settings):
        self.settings = settings
        self.opener = build_opener(NoModelRedirect())

    def complete(self, system_prompt, user_text, schema=None):
        deepseek = self.settings.provider == 'deepseek'
        label = 'DeepSeek' if deepseek else '兼容 API'
        key_setting = 'DEEPSEEK_API_KEY' if deepseek else 'LLM_API_KEY'
        model_setting = 'DEEPSEEK_MODEL' if deepseek else 'LLM_MODEL'
        if not self.settings.api_key:
            raise ModelUnavailableError(f'未配置 {label} 密钥，请在后端环境变量或 .env 中设置 {key_setting}。')
        if schema is not None:
            system_prompt += "\n只输出 JSON，输出 JSON 必须满足以下 JSON Schema：\n" + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
        body = {"model":self.settings.model, "stream":False,
                self.settings.token_limit_param:self.settings.max_tokens,
                "messages":[{"role":"system", "content":system_prompt}, {"role":"user", "content":user_text}]}
        if deepseek:
            body.update(temperature=0, thinking={'type':'disabled'})
        if self.settings.json_mode == 'json_object':
            body['response_format'] = {'type':'json_object'}
        request = Request(self.settings.base_url + "/chat/completions", data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                          headers={"Content-Type":"application/json", "Authorization":"Bearer " + self.settings.api_key}, method="POST")
        try:
            with self.opener.open(request, timeout=self.settings.timeout) as response:
                getheader = getattr(response, 'getheader', None)
                declared = getheader('Content-Length') if callable(getheader) else None
                if declared is not None:
                    if not re.fullmatch(r'[0-9]{1,20}', declared.strip()):
                        raise ModelOutputError(f'{label} 响应长度无效，已拒绝使用。')
                    declared = int(declared)
                    if declared > self.MAX_RESPONSE_BYTES:
                        raise ModelOutputError(f'{label} 响应超过大小限制，已拒绝使用。')
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
                if declared is not None and len(raw) != declared:
                    raise ModelOutputError(f'{label} 响应不完整，已拒绝使用。')
        except HTTPError as exc:
            status = exc.code
            exc.close()
            messages = {401:f"API 密钥无效，请检查 {key_setting}。", 402:"API 余额不足，请检查账户额度。",
                        429:"API 请求被限流，请稍后重试。", 400:"API 请求参数不被接受，请检查模型和配置。",
                        404:f"API 模型或地址不存在，请检查 {model_setting} 与服务地址。"}
            detail = messages.get(status, "API 服务暂不可用，请稍后重试。")
            raise ModelUnavailableError(f"{label} HTTP {status}：{detail}") from None
        except IncompleteRead:
            raise ModelOutputError(f"{label} 响应不完整，已拒绝使用；请重新分析任务。") from None
        except HTTPException:
            raise ModelOutputError(f"{label} 返回了异常的 HTTP 响应，已拒绝使用。") from None
        except (URLError, TimeoutError, ConnectionError, OSError):
            raise ModelUnavailableError(f"{label} 连接失败或超时，请检查网络后重试。") from None
        if len(raw) > self.MAX_RESPONSE_BYTES:
            raise ModelOutputError(f"{label} 响应超过大小限制，已拒绝使用。")
        try:
            payload = json.loads(raw.decode("utf-8"))
            choice = payload["choices"][0]
            message = choice["message"]
            finish = choice["finish_reason"]
            content = message["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise ModelOutputError(f"{label} 未返回有效的模型响应结构。") from None
        if finish == "length":
            raise ModelOutputError(f"{label} 输出被截断，已拒绝生成候选；请缩短任务或调整 LLM_MAX_TOKENS。")
        if finish != "stop" or message.get("refusal") or not isinstance(content, str) or not content.strip():
            raise ModelOutputError(f"{label} 未正常返回完整文本，已拒绝生成候选。")
        return content


# Preserve the import used by existing integrations and transport tests.
DeepSeekClient = ChatCompletionsClient
