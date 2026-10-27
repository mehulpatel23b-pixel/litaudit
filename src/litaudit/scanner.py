"""litaudit rule engine — static security checks for LiteLLM-style
gateway configs.

Rule numbering is stable and referenced from the README table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .tinyyaml import parse, YamlError


# ---------------------------------------------------------------- severities

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    where: str
    message: str
    fix: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "where": self.where,
            "message": self.message,
            "fix": self.fix,
        }


def _masked(value: str) -> str:
    value = str(value)
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "…" + value[-2:]


_SECRET_PATTERNS = [
    (re.compile(r"^sk-[A-Za-z0-9]{16,}$"), "OpenAI-style key"),
    (re.compile(r"^sk-ant-[A-Za-z0-9\-_]{16,}$"), "Anthropic key"),
    (re.compile(r"^ghp_[A-Za-z0-9]{20,}$"), "GitHub token"),
    (re.compile(r"^gho_[A-Za-z0-9]{20,}$"), "GitHub OAuth token"),
    (re.compile(r"^AKIA[0-9A-Z]{16}$"), "AWS access key"),
    (re.compile(r"^AIza[0-9A-Za-z\-_]{30,}$"), "Google API key"),
    (re.compile(r"^xai-[A-Za-z0-9]{20,}$"), "xAI key"),
]

_WEAK_KEYS = {
    "changeme", "change-me", "sk-1234", "sk-123456", "your-api-key",
    "your_api_key", "yourkey", "test", "admin", "password", "secret",
    "master_key", "none", "null", "masterkey", "master",
}

_ENV_REF = re.compile(r"^os\.environ/[\w\-]+$")


def _looks_secret(value: str) -> Optional[str]:
    for pattern, label in _SECRET_PATTERNS:
        if pattern.match(str(value).strip()):
            return label
    return None


def _is_env(value: str) -> bool:
    return bool(_ENV_REF.match(str(value).strip()))


def _iter_secret_fields(d: Dict[str, Any], path: str = ""):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from _iter_secret_fields(v, f"{path}{k}.")
        elif isinstance(v, str) and ("key" in k.lower() or "secret" in k.lower()
                                    or "password" in k.lower() or "token" in k.lower()):
            yield f"{path}{k}", v


def _find_all(obj: Any, key: str):
    """Yield (path, value) for every occurrence of ``key`` in nested structures."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                yield k, v
            yield from _find_all(v, key)
    elif isinstance(obj, list):
        for item in obj:
            yield from _find_all(item, key)


def _has_any_key(obj: Any, needles) -> bool:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if any(n in str(k).lower() for n in needles):
                return True
            if _has_any_key(v, needles):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if _has_any_key(item, needles):
                return True
    return False


_DB_URL_RE = re.compile(
    r"^postgres(?:ql)?://([^:@/\s]+):([^@/\s]+)@|^mysql://([^:@/\s]+):([^@/\s]+)@"
    r"|^redis://:([^@\s]+)@|^rediss://:([^@\s]+)@",
    re.IGNORECASE,
)


def scan_config(path: str) -> Dict[str, Any]:
    """Audit one config file. Returns {"findings": [...], "error": None|str}."""
    findings: List[Finding] = []
    try:
        text = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError as exc:
        return {"findings": [], "error": f"cannot read file: {exc}"}
    try:
        doc = parse(text)
    except YamlError as exc:
        return {"findings": [], "error": f"cannot parse YAML: {exc}"}
    if not isinstance(doc, dict):
        return {"findings": [], "error": "document did not parse to a mapping"}

    model_list = doc.get("model_list") or []
    general = doc.get("general_settings") or {}
    litellm_settings = doc.get("litellm_settings") or {}
    router = doc.get("router_settings") or {}
    callbacks = doc.get("callbacks") or doc.get("callback_settings") or {}
    env_block = doc.get("environment_variables") or {}

    # ---------- LIT-001: hardcoded master key -------------------------------
    master = None
    for _, v in _find_all(doc, "master_key"):
        master = v
    if master is not None:
        if _is_env(str(master)):
            pass  # good practice
        elif str(master).strip().lower() in _WEAK_KEYS:
            findings.append(Finding(
                "LIT-001", "critical", "general_settings.master_key",
                f"master_key set to a placeholder value ({_masked(str(master))})",
                "rotate the master key to a long random value and inject it via "
                "os.environ/MASTER_KEY"))
        elif _looks_secret(str(master)):
            findings.append(Finding(
                "LIT-001", "critical", "general_settings.master_key",
                "master_key literal committed to config (looks like a live secret, "
                f"matched {_looks_secret(str(master))})",
                "rotate immediately and reference os.environ/MASTER_KEY instead — a leaked "
                "master key granted owner-level org access in the Oct-2026 LiteLLM incident"))
        elif len(str(master)) < 20:
            findings.append(Finding(
                "LIT-001", "high", "general_settings.master_key",
                f"master_key literal is committed and short ({len(str(master))} chars)",
                "never commit the master key; use os.environ/MASTER_KEY"))
        else:
            findings.append(Finding(
                "LIT-001", "critical", "general_settings.master_key",
                "master_key literal committed to config — any copy of this file "
                "grants full admin over the proxy",
                "rotate immediately and reference os.environ/MASTER_KEY"))

    # ---------- LIT-002: provider api_key literals ---------------------------
    if isinstance(model_list, list):
        for idx, entry in enumerate(model_list):
            if not isinstance(entry, dict):
                continue
            lp = entry.get("litellm_params") or {}
            if not isinstance(lp, dict):
                continue
            key = lp.get("api_key")
            where = f"model_list[{idx}].litellm_params.api_key"
            label = entry.get("model_name", f"#{idx}")
            if key is None:
                continue
            skey = str(key)
            if _is_env(skey):
                continue
            weak = skey.strip().lower() in _WEAK_KEYS
            secret = _looks_secret(skey)
            if weak or secret or not skey.startswith("os.environ"):
                sev = "critical" if secret else "high"
                msg = (f"provider api_key literal (model '{label}') "
                       f"{'matches ' + secret if secret else 'value=' + _masked(skey)}")
                findings.append(Finding(
                    "LIT-002", sev, where, msg,
                    "store provider keys in the environment and reference them as "
                    "os.environ/PROVIDER_KEY in litellm_params"))

    # ---------- LIT-003: credential-bearing database_url ----------------------
    for k, v in _find_all(doc, "database_url"):
        s = str(v)
        m = _DB_URL_RE.search(s)
        if m and not _is_env(s):
            findings.append(Finding(
                "LIT-003", "high", "general_settings.database_url",
                "database_url is a literal with an embedded username:password",
                "move the connection string to an environment variable "
                "(os.environ/DATABASE_URL); a leaked DB URL exposes the spend "
                "tracking tables that hold every virtual key"))

    # ---------- LIT-004: plaintext secrets in environment_variables ----------
    if isinstance(env_block, dict):
        for k, v in env_block.items():
            if not isinstance(v, str):
                continue
            secret = _looks_secret(v)
            if secret:
                findings.append(Finding(
                    "LIT-004", "critical", f"environment_variables.{k}",
                    f"plaintext {secret} baked into environment_variables",
                    "inject the real value at deploy time; never commit it — "
                    "configs like this are exactly what leaked in the "
                    "Oct-2026 LiteLLM supply-chain incident"))

    # ---------- LIT-005: plaintext http:// api_base ---------------------------
    for k, v in _find_all(doc, "api_base"):
        s = str(v)
        if s.startswith("http://") and "localhost" not in s and "127.0.0.1" not in s:
            findings.append(Finding(
                "LIT-005", "medium", "litellm_params.api_base",
                f"provider endpoint uses plaintext http:// ({_masked(s)})",
                "use https:// endpoints; plaintext routes every prompt and "
                "API key over an interceptable channel"))

    # ---------- LIT-006: no master_key configured -----------------------------
    if master is None:
        has_key_auth = _has_any_key(doc, ["allowed_model", "virtual_key"])
        findings.append(Finding(
            "LIT-006", "medium" if has_key_auth else "high",
            "general_settings",
            "no master_key configured — the proxy's admin surface has no "
            "dedicated admin credential",
            "set general_settings.master_key from the environment; without it, "
            "management endpoints rely on whatever auth mode is active and any "
            "misconfiguration becomes unauthenticated admin access"))

    # ---------- LIT-007: wildcard model routes --------------------------------
    if isinstance(model_list, list):
        for idx, entry in enumerate(model_list):
            if isinstance(entry, dict):
                name = entry.get("model_name")
                if isinstance(name, str) and name.strip() in ("*", "**"):
                    findings.append(Finding(
                        "LIT-007", "medium", f"model_list[{idx}].model_name",
                        "wildcard model route exposes every provider model behind "
                        "one key",
                        "pin model_name to the specific deployments callers should "
                        "reach, or guard wildcards with allowed_model_lists"))

    # ---------- LIT-008: no spend/rate controls -------------------------------
    controls = _has_any_key(doc, ["max_budget", "budget_duration", "rpm",
                                  "tpm", "max_parallel_requests", "max_tokens"])
    if not controls:
        findings.append(Finding(
            "LIT-008", "medium", "model_list / router_settings",
            "no budget, spend or rate limit found anywhere in the config",
            "set router Settings.max_budget / budget_duration per key and team, "
            "plus tpm/rpm limits — a single runaway agent loop otherwise bills "
            "your provider cap straight to zero"))

    # ---------- LIT-009: telemetry not explicitly disabled -------------------
    if not isinstance(litellm_settings, dict) or litellm_settings.get("telemetry") is not False:
        findings.append(Finding(
            "LIT-009", "low", "litellm_settings.telemetry",
            "usage telemetry is not explicitly disabled",
            "for privacy-sensitive deployments set litellm_settings.telemetry: "
            "false (requests are otherwise reported to LiteLLM's telemetry "
            "collector)"))

    # ---------- LIT-010: callbacks shipping data to external URLs ------------
    cb_urls: List[str] = []
    if isinstance(callbacks, dict):
        for k, v in callbacks.items():
            if isinstance(v, str) and v.startswith(("http://", "https://")):
                cb_urls.append(f"callbacks.{k}")
    elif isinstance(callbacks, list):
        for i, item in enumerate(callbacks):
            if isinstance(item, str) and item.startswith(("http://", "https://")):
                cb_urls.append(f"callbacks[{i}]")
    for where in cb_urls:
        findings.append(Finding(
            "LIT-010", "medium", where,
            "callback points at a remote URL — prompts/responses can leave "
            "your perimeter",
            "audit callback endpoints like you audit code dependencies: they "
            "receive full request payloads and a rotated or hijacked endpoint "
            "turns the proxy into an exfiltration channel"))

    # ---------- LIT-011: generic key-like literals naming known safewords ------
    for path, value in _iter_secret_fields(doc):
        if isinstance(value, str) and _is_env(value):
            continue
        if isinstance(value, str) and value.strip().lower() in _WEAK_KEYS and "master" not in path.lower():
            findings.append(Finding(
                "LIT-011", "high", path,
                f"key field holds a weak/placeholder value ({value!r})",
                "weak credentials will pass a config that 'looks right' while "
                "granting anyone the door; replace and inject real values"))

    return {"findings": findings, "error": None}
