from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import math
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status


APP_VERSION = "1.2.0"
GATEWAY_API_TOKEN = os.environ.get("GATEWAY_API_TOKEN", "").strip()
DEFAULT_LLM_BASE_URL = "http://192.0.2.10:8081"
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", DEFAULT_LLM_BASE_URL).rstrip("/")
LLM_UPSTREAM_NAME = os.environ.get("LLM_UPSTREAM_NAME", "node2").strip() or "node2"
MEMORY_API_URL = os.environ.get("MEMORY_API_URL", "http://192.0.2.10:8765").rstrip("/")
MEMORY_API_TOKEN = os.environ.get("MEMORY_API_TOKEN", "").strip()
MAX_MEMORY_NOTES = int(os.environ.get("MAX_MEMORY_NOTES", "5"))
MAX_CONTEXT_NOTES = int(os.environ.get("MAX_CONTEXT_NOTES", "4"))
SEARCH_CANDIDATE_LIMIT = int(os.environ.get("SEARCH_CANDIDATE_LIMIT", "4"))
MEMORY_RELATED_LIMIT = int(os.environ.get("MEMORY_RELATED_LIMIT", "3"))
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT_SECONDS", "300"))
MAX_STALE_NOTE_AGE_DAYS = int(os.environ.get("MAX_STALE_NOTE_AGE_DAYS", "45"))
REVIEW_GRACE_DAYS = int(os.environ.get("REVIEW_GRACE_DAYS", "3"))
AUTO_REMEMBER_ENABLED = os.environ.get("AUTO_REMEMBER_ENABLED", "false").lower() == "true"
AUTO_REMEMBER_MIN_CHARS = int(os.environ.get("AUTO_REMEMBER_MIN_CHARS", "140"))
AUTO_REMEMBER_MAX_ITEMS = int(os.environ.get("AUTO_REMEMBER_MAX_ITEMS", "3"))
AUTO_REMEMBER_LAST_MESSAGES = int(os.environ.get("AUTO_REMEMBER_LAST_MESSAGES", "6"))
AUTO_REMEMBER_MAX_TOKENS = int(os.environ.get("AUTO_REMEMBER_MAX_TOKENS", "700"))
EMBED_API_URL = os.environ.get("EMBED_API_URL", "").rstrip("/")  # BGE-M3 (node2, OpenAI-kompatibel) fuer semantic reranking
EMBED_MODEL = os.environ.get("EMBED_MODEL", "bge-m3")
AUTO_REMEMBER_ALLOWED_CATEGORIES = {
    item.strip().lower()
    for item in os.environ.get("AUTO_REMEMBER_ALLOWED_CATEGORIES", "fact,preference,decision").split(",")
    if item.strip()
}

OPS_KEYWORDS = {
    "alert",
    "availability",
    "broken",
    "container",
    "cpu",
    "disk",
    "docker",
    "error",
    "failing",
    "health",
    "home assistant",
    "incident",
    "latency",
    "log",
    "memory",
    "network",
    "offline",
    "problem",
    "restart",
    "service",
    "status",
    "systemd",
    "unavailable",
}
SOURCE_KEYWORDS = {
    ".py",
    ".yaml",
    ".yml",
    "api",
    "code",
    "compose",
    "config",
    "dockerfile",
    "endpoint",
    "env",
    "function",
    "implementation",
    "line",
    "module",
    "repo",
    "script",
    "source",
    "stack trace",
    "traceback",
}
MEMORY_KEYWORDS = {
    "always",
    "decision",
    "documented",
    "habit",
    "known fix",
    "note",
    "obsidian",
    "prefer",
    "preference",
    "remember",
    "usually",
}
GENERIC_QUERY_TOKENS = {
    "a",
    "an",
    "bei",
    "behebe",
    "beheben",
    "das",
    "den",
    "der",
    "die",
    "einen",
    "einer",
    "eines",
    "ein",
    "for",
    "how",
    "ich",
    "ist",
    "mit",
    "nur",
    "the",
    "und",
    "was",
    "wie",
    "why",
    "wieso",
    "wo",
}
SECURITY_KEYWORDS = {
    "auth",
    "credential",
    "firewall",
    "hardening",
    "password",
    "rotate",
    "secret",
    "secure",
    "security",
    "ssh",
    "token",
    "ufw",
    "vulnerability",
}
ALLOWED_MEMORY_CATEGORIES = {"fact", "preference", "decision", "incident", "fix", "runbook"}
SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[-_ ]?key|token|secret|password|passwd|private key)\b"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
]
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.*)$")
SEARCH_PLANS: dict[str, list[dict[str, Any]]] = {
    "ops": [
        {"source_space": "homelab", "note_type": "runbook", "rag_include": True, "limit": 3},
        {"source_space": "homelab", "note_type": "fix", "rag_include": True, "limit": 3},
        {"source_space": "homelab", "knowledge_class": "operational_knowledge", "rag_include": True, "limit": 4},
        {"source_space": "homelab", "note_type": "incident", "status": "active", "rag_include": True, "limit": 3},
        {"source_space": "ops_events", "note_type": "incident", "rag_include": True, "limit": 3},
        {"source_space": "ops_events", "note_type": "timeline", "rag_include": True, "limit": 2},
        {"source_space": "ops_events", "note_type": "correlation", "rag_include": True, "limit": 2},
        {"source_space": "homelab", "knowledge_class": "derived_insight", "rag_include": True, "limit": 3},
        {"source_space": "homelab", "note_type": "source-brief", "limit": 2},
        {"source_space": "homelab", "note_type": "source-doc", "rag_include": False, "limit": 1},
    ],
    "source": [
        {"source_space": "homelab", "note_type": "source-brief", "limit": 4},
        {"source_space": "homelab", "note_type": "source-doc", "rag_include": False, "limit": 3},
        {"source_space": "homelab", "knowledge_class": "derived_insight", "rag_include": True, "limit": 2},
    ],
    "memory": [
        {"source_space": "homelab", "knowledge_class": "evergreen_knowledge", "rag_include": True, "limit": 4},
        {"source_space": "homelab", "knowledge_class": "operational_knowledge", "rag_include": True, "limit": 3},
        {"source_space": "homelab", "knowledge_class": "derived_insight", "rag_include": True, "limit": 2},
    ],
    "security": [
        {"source_space": "homelab", "note_type": "runbook", "rag_include": True, "limit": 3},
        {"source_space": "homelab", "note_type": "fix", "rag_include": True, "limit": 3},
        {"source_space": "homelab", "knowledge_class": "operational_knowledge", "rag_include": True, "limit": 4},
        {"source_space": "homelab", "knowledge_class": "derived_insight", "rag_include": True, "limit": 3},
        {"source_space": "homelab", "note_type": "incident", "status": "active", "rag_include": True, "limit": 2},
        {"source_space": "ops_events", "note_type": "incident", "rag_include": True, "limit": 2},
        {"source_space": "ops_events", "note_type": "timeline", "rag_include": True, "limit": 2},
        {"source_space": "ops_events", "note_type": "correlation", "rag_include": True, "limit": 2},
        {"source_space": "homelab", "note_type": "source-doc", "rag_include": False, "limit": 1},
    ],
    "general": [
        {"source_space": "homelab", "knowledge_class": "evergreen_knowledge", "rag_include": True, "limit": 3},
        {"source_space": "homelab", "knowledge_class": "operational_knowledge", "rag_include": True, "limit": 3},
        {"source_space": "homelab", "knowledge_class": "derived_insight", "rag_include": True, "limit": 2},
        {"source_space": "homelab", "note_type": "source-brief", "limit": 1},
    ],
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Memory Gateway", version=APP_VERSION, docs_url=None, redoc_url=None, openapi_url=None)


def require_gateway_auth(authorization: str | None = Header(default=None)) -> None:
    if not GATEWAY_API_TOKEN:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token.",
        )
    supplied_token = authorization.removeprefix("Bearer ").strip()
    if not secrets.compare_digest(supplied_token, GATEWAY_API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token.",
        )


def memory_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if MEMORY_API_TOKEN:
        headers["Authorization"] = f"Bearer {MEMORY_API_TOKEN}"
    return headers


def extract_text(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                parts.append(item["text"].strip())
        return "\n".join(part for part in parts if part)
    return ""


def latest_user_message(messages: list[dict[str, Any]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            text = extract_text(message.get("content"))
            if text:
                return text
    return ""


def latest_assistant_message(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return ""
    return extract_text(message.get("content"))


def collapse_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return cleaned or "memory"


def tokenize_query(value: str) -> list[str]:
    return [token for token in re.findall(r"[a-z0-9_./-]+", value.lower()) if len(token) > 2]


def focus_query_tokens(value: str) -> set[str]:
    return {token for token in tokenize_query(value) if token not in GENERIC_QUERY_TOKENS}


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def note_frontmatter(note: dict[str, Any]) -> dict[str, Any]:
    frontmatter = note.get("frontmatter")
    return frontmatter if isinstance(frontmatter, dict) else {}


def note_metadata(note: dict[str, Any]) -> dict[str, Any]:
    metadata = note.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def note_tags(note: dict[str, Any]) -> set[str]:
    return {
        str(tag).lower()
        for tag in note.get("tags", [])
        if isinstance(tag, str) and tag.strip()
    }


def note_candidate_paths(note: dict[str, Any]) -> set[str]:
    frontmatter = note_frontmatter(note)
    raw = frontmatter.get("candidate_paths")
    if not isinstance(raw, list):
        return set()
    candidates: set[str] = set()
    for item in raw:
        if isinstance(item, str) and item.strip():
            candidates.add(item.strip().removesuffix(".md"))
            candidates.add(f"{item.strip().removesuffix('.md')}.md")
    return candidates


def note_topic_tokens(note: dict[str, Any]) -> set[str]:
    frontmatter = note_frontmatter(note)
    metadata = note_metadata(note)
    values: list[str] = [
        str(note.get("path") or ""),
        str(note.get("title") or ""),
        str(frontmatter.get("kind") or ""),
        str(frontmatter.get("incident_service") or ""),
        str(frontmatter.get("incident_host") or ""),
        str(metadata.get("note_type") or ""),
        str(metadata.get("source_space") or ""),
    ]
    for collection in (
        note.get("tags"),
        frontmatter.get("tags"),
        frontmatter.get("services"),
        frontmatter.get("hosts"),
    ):
        if isinstance(collection, list):
            values.extend(str(item) for item in collection if isinstance(item, str))
    tokens: set[str] = set()
    for value in values:
        tokens.update(focus_query_tokens(value))
    return tokens


def review_interval_days(frontmatter: dict[str, Any]) -> int:
    value = frontmatter.get("review_interval_days")
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return 30
    return max(parsed, 1)


def note_updated_at(note: dict[str, Any]) -> datetime | None:
    frontmatter = note_frontmatter(note)
    for key in ("updated", "last_reviewed", "created"):
        parsed = parse_timestamp(frontmatter.get(key))
        if parsed:
            return parsed
    return parse_timestamp(note.get("updated_at"))


def note_age_days(note: dict[str, Any]) -> int | None:
    updated = note_updated_at(note)
    if not updated:
        return None
    return max((datetime.now(timezone.utc) - updated).days, 0)


def governance_flags(note: dict[str, Any]) -> list[str]:
    frontmatter = note_frontmatter(note)
    kind = str(frontmatter.get("kind") or "").lower()
    flags: list[str] = []
    age_days = note_age_days(note)

    if str(frontmatter.get("maintenance_status") or "").lower() == "stale":
        flags.append("stale")
    if age_days is not None and age_days > MAX_STALE_NOTE_AGE_DAYS:
        flags.append("aging")

    if kind in {"runbook", "fix"}:
        if not frontmatter.get("schema_version"):
            flags.append("missing-schema")
        if not str(frontmatter.get("owner") or "").strip():
            flags.append("missing-owner")
        if not parse_timestamp(frontmatter.get("last_reviewed")):
            flags.append("missing-review")
        else:
            due_at = parse_timestamp(frontmatter.get("last_reviewed"))
            if due_at and datetime.now(timezone.utc) - due_at > timedelta(days=review_interval_days(frontmatter) + REVIEW_GRACE_DAYS):
                flags.append("review-overdue")
        approved_commands = frontmatter.get("approved_commands")
        if frontmatter.get("safe_to_auto_apply") and not isinstance(approved_commands, list):
            flags.append("unsafe-auto-apply")
        if frontmatter.get("safe_to_auto_apply") and isinstance(approved_commands, list) and not approved_commands:
            flags.append("unsafe-auto-apply")
        if str(frontmatter.get("review_status") or "").lower() in {"pending-review", "needs-review", "overdue"}:
            flags.append("review-pending")

    if kind == "maintenance-conflict":
        flags.append("conflict")

    return sorted(set(flags))


def note_freshness(note: dict[str, Any]) -> str:
    flags = set(governance_flags(note))
    if {"stale", "review-overdue", "unsafe-auto-apply", "conflict"} & flags:
        return "warning"
    if {"aging", "missing-review", "missing-owner", "missing-schema", "review-pending"} & flags:
        return "review"
    return "fresh"


def classify_query(query: str) -> str:
    lowered = query.lower()
    scores = {
        "ops": sum(1 for keyword in OPS_KEYWORDS if keyword in lowered),
        "source": sum(1 for keyword in SOURCE_KEYWORDS if keyword in lowered),
        "memory": sum(1 for keyword in MEMORY_KEYWORDS if keyword in lowered),
        "security": sum(1 for keyword in SECURITY_KEYWORDS if keyword in lowered),
    }
    if scores["security"] >= 1:
        return "security"
    if scores["source"] >= max(scores["ops"], scores["memory"], 1):
        return "source"
    if scores["ops"] >= max(scores["memory"], 1):
        return "ops"
    if scores["memory"] >= 1:
        return "memory"
    return "general"


async def memory_search(
    client: httpx.AsyncClient,
    query: str,
    *,
    limit: int,
    filters: dict[str, Any],
) -> list[dict[str, Any]]:
    payload: dict[str, Any] = {
        "query": query,
        "limit": max(1, min(limit, SEARCH_CANDIDATE_LIMIT)),
        "include_content": True,
        "include_related": True,
        "related_limit": max(0, min(MEMORY_RELATED_LIMIT, 20)),
    }
    payload.update(filters)
    response = await client.post(
        f"{MEMORY_API_URL}/search",
        headers=memory_headers(),
        json=payload,
    )
    response.raise_for_status()
    data = response.json()
    notes: list[dict[str, Any]] = []
    results = data.get("results")
    if isinstance(results, list):
        notes.extend(item for item in results if isinstance(item, dict))
    related = data.get("related")
    if isinstance(related, list):
        for item in related:
            if not isinstance(item, dict):
                continue
            candidate = dict(item)
            candidate["_related"] = True
            candidate["_related_anchor_path"] = item.get("anchor_path")
            candidate["_relation_type"] = item.get("relation_type")
            candidate["_relation_direction"] = item.get("relation_direction")
            notes.append(candidate)
    return notes


async def memory_list(
    client: httpx.AsyncClient,
    *,
    folder: str,
    kind: str | None = None,
    limit: int = 5,
    path_prefix: str | None = None,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {
        "folder": folder,
        "limit": max(1, min(limit, MAX_MEMORY_NOTES)),
    }
    if kind:
        params["kind"] = kind
    if path_prefix:
        params["path_prefix"] = path_prefix
    response = await client.get(
        f"{MEMORY_API_URL}/notes/list",
        headers=memory_headers(),
        params=params,
    )
    response.raise_for_status()
    data = response.json()
    results = data.get("results")
    if isinstance(results, list):
        return [item for item in results if isinstance(item, dict)]
    return []


async def memory_get_note(client: httpx.AsyncClient, *, path: str) -> dict[str, Any] | None:
    response = await client.get(
        f"{MEMORY_API_URL}/notes",
        headers=memory_headers(),
        params={"path": path},
    )
    response.raise_for_status()
    data = response.json()
    return data if isinstance(data, dict) else None


def score_note(note: dict[str, Any], query: str, profile: str, order_index: int) -> float:
    path = str(note.get("path") or "")
    title = str(note.get("title") or "")
    excerpt = str(note.get("excerpt") or "")
    frontmatter = note_frontmatter(note)
    metadata = note_metadata(note)
    tags = note_tags(note)
    kind = str(frontmatter.get("kind") or "").lower()
    review_status = str(frontmatter.get("review_status") or "").lower()
    captured_by = str(frontmatter.get("captured_by") or "").lower()
    source_space = str(metadata.get("source_space") or "")
    knowledge_class = str(metadata.get("knowledge_class") or "")
    retrieval_tier = str(metadata.get("retrieval_tier") or "")
    source_type = str(metadata.get("source_type") or "")

    score = 100.0 - (order_index * 1.5)
    lowered_path = path.lower()
    lowered_title = title.lower()
    lowered_excerpt = excerpt.lower()
    query_tokens = tokenize_query(query)
    focus_tokens = focus_query_tokens(query)
    topic_overlap = note_topic_tokens(note) & focus_tokens

    if note.get("_related"):
        score -= 18
        if note.get("_relation_type") in {"solved_by", "depends_on", "implemented_by"}:
            score += 6

    score += float(metadata.get("source_priority") or 0)
    if metadata.get("rag_include") is False:
        score -= 20
    if source_space == "homelab":
        score += 12
    elif source_space == "reference":
        score -= 35
    elif source_space == "selfbrain":
        score -= 20 if profile != "memory" else 6

    if retrieval_tier == "primary":
        score += 12
    elif retrieval_tier == "secondary":
        score += 4
    elif retrieval_tier in {"reference", "archive", "archived"}:
        score -= 8
    elif retrieval_tier == "personalization":
        score -= 6

    if knowledge_class == "operational_knowledge":
        score += 12
    elif knowledge_class == "derived_insight":
        score += 8
    elif knowledge_class == "evergreen_knowledge":
        score += 10
    elif knowledge_class in {"raw_evidence", "archived_material"}:
        score -= 10
    if source_type == "external_reference":
        score -= 20
    elif source_type in {"summarized", "self_tested"}:
        score += 6
    if captured_by == "memory-gateway":
        score -= 18
    if review_status in {"captured", "pending-review", "needs-review"}:
        score -= 10
    if topic_overlap:
        score += min(len(topic_overlap), 3) * 14

    if profile == "ops":
        if lowered_path.startswith("ops/"):
            score += 35
        if lowered_path.startswith("memory/runbooks/"):
            score += 18
        if lowered_path.startswith("memory/fixes/"):
            score += 14
        if kind == "runbook":
            score += 34
        if kind == "fix":
            score += 30
        if kind == "remediation-plan":
            score += 14
        if kind == "incident":
            score += 10
        if kind == "ops-summary":
            score += 12
        if {"ops", "incident"} & tags:
            score += 12
        if kind in {"remediation-plan", "incident", "ops-summary"} and focus_tokens and not topic_overlap:
            score -= 90
        if kind in {"source-brief", "source-doc", "git-repo"} and focus_tokens and not topic_overlap:
            score -= 80
    elif profile == "source":
        if lowered_path.startswith("sources/"):
            score += 35
        if kind == "source-brief":
            score += 28
        if kind == "source-doc":
            score += 12
        if kind == "git-repo":
            score += 18
        if "source" in tags:
            score += 12
        if note.get("line_start") is not None and note.get("line_end") is not None:
            score += 6
    elif profile == "memory":
        if lowered_path.startswith("memory/"):
            score += 35
        if kind.startswith("memory-") or kind in {"fix", "incident", "runbook", "remediation-plan"}:
            score += 20
        if {"preference", "decision", "fact"} & tags:
            score += 10
    elif profile == "security":
        if "security" in tags:
            score += 18
        if lowered_path.startswith("memory/runbooks/"):
            score += 16
        if lowered_path.startswith("memory/maintenance/"):
            score += 10
        if "hardening" in lowered_title or "ssh" in lowered_title:
            score += 10
        if kind in {"remediation-plan", "incident", "ops-summary"} and focus_tokens and not topic_overlap:
            score -= 90
        if kind in {"source-brief", "source-doc", "git-repo"} and focus_tokens and not topic_overlap:
            score -= 80
    if kind == "maintenance-report":
        score += 16 if profile in {"ops", "security"} else 6
    if kind == "maintenance-conflict":
        score += 18 if profile in {"ops", "security"} else 4
    if kind == "maintenance-review-backlog":
        score += 14 if profile in {"ops", "security"} else 3
    if (
        kind in {"maintenance-report", "maintenance-conflict", "maintenance-review-backlog"}
        and profile in {"ops", "security"}
        and focus_tokens
        and not topic_overlap
    ):
        score -= 75

    for token in query_tokens:
        if token in lowered_title:
            score += 5
        if token in lowered_path:
            score += 4
        if token in lowered_excerpt:
            score += 2

    updated = parse_timestamp(frontmatter.get("updated") or frontmatter.get("created"))
    if updated:
        age_days = max((datetime.now(timezone.utc) - updated).days, 0)
        if age_days <= 7:
            score += 6
        elif age_days <= 30:
            score += 3
        elif age_days > MAX_STALE_NOTE_AGE_DAYS:
            score -= 8

    flags = set(governance_flags(note))
    if "stale" in flags:
        score -= 30
    if "review-overdue" in flags:
        score -= 24
    if "review-pending" in flags:
        score -= 12
    if "missing-review" in flags:
        score -= 8
    if "missing-owner" in flags:
        score -= 5
    if "missing-schema" in flags:
        score -= 5
    if "unsafe-auto-apply" in flags:
        score -= 35
    if kind in {"runbook", "fix"} and not flags:
        score += 12
    elif kind in {"runbook", "fix"} and {"missing-review", "missing-owner", "missing-schema", "review-overdue", "unsafe-auto-apply"} & flags:
        score -= 6

    return score


def compact_note_body(note: dict[str, Any], query: str) -> str:
    content = str(note.get("content") or "").strip()
    excerpt = str(note.get("excerpt") or "").strip()
    frontmatter = note_frontmatter(note)
    kind = str(frontmatter.get("kind") or "").lower()
    if kind in {"runbook", "fix"} and content:
        lines = [line.rstrip() for line in content.splitlines() if line.strip()]
        selected: list[str] = []
        allowed_sections = {"zweck", "purpose", "voraussetzungen", "preconditions", "schritte", "steps", "verifikation", "verification", "sicherheitsnotizen", "safety notes"}
        include_section = True
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("## "):
                section_name = stripped[3:].strip().lower()
                include_section = section_name in allowed_sections
            if include_section or stripped.startswith("# "):
                selected.append(stripped)
        approved_commands = frontmatter.get("approved_commands")
        if isinstance(approved_commands, list) and approved_commands:
            selected.append(f"Approved commands: {'; '.join(str(item) for item in approved_commands[:6])}")
        snippet = "\n".join(selected).strip()
        if snippet:
            return snippet[:1600]
    if excerpt:
        return excerpt[:500]
    if not content:
        return ""
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    query_tokens = tokenize_query(query)
    relevant: list[str] = []
    for line in lines:
        lowered = line.lower()
        if any(token in lowered for token in query_tokens):
            relevant.append(line)
        if len(relevant) >= 5:
            break
    snippet = "\n".join(relevant or lines[:5])
    return snippet[:700]


def parse_markdown_sections(content: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        heading_match = HEADING_PATTERN.match(line.strip())
        if heading_match and len(heading_match.group(1)) == 2:
            current = heading_match.group(2).strip().lower()
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(line)
    return sections


def normalize_section_items(lines: list[str]) -> list[str]:
    items: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        line = re.sub(r"^\d+\.\s+", "", line)
        line = re.sub(r"^[-*+]\s+", "", line)
        if line:
            items.append(line)
    return items


def render_grounded_note_response(note: dict[str, Any]) -> str:
    content = str(note.get("content") or "").strip()
    frontmatter = note_frontmatter(note)
    sections = parse_markdown_sections(content)

    purpose_lines = normalize_section_items(sections.get("zweck", []) or sections.get("purpose", []))
    steps = normalize_section_items(sections.get("schritte", []) or sections.get("steps", []))
    verification = normalize_section_items(sections.get("verifikation", []) or sections.get("verification", []))
    safety = normalize_section_items(sections.get("sicherheitsnotizen", []) or sections.get("safety notes", []))
    approved_commands = frontmatter.get("approved_commands")

    lines = ["### Kurzdiagnose"]
    if purpose_lines:
        lines.extend(f"- {line}" for line in purpose_lines[:2])
    else:
        lines.append("- nicht im Runbook dokumentiert")

    lines.extend(["", "### Schritte"])
    if steps:
        lines.extend(f"{index}. {step}" for index, step in enumerate(steps[:6], start=1))
    else:
        lines.append("- nicht im Runbook dokumentiert")

    lines.extend(["", "### Freigegebene Befehle"])
    if isinstance(approved_commands, list) and approved_commands:
        lines.extend(f"- `{str(command)}`" for command in approved_commands[:6])
    else:
        lines.append("- nicht im Runbook dokumentiert")

    lines.extend(["", "### Nicht tun"])
    if safety:
        lines.extend(f"- {item}" for item in safety[:5])
    else:
        lines.append("- nicht im Runbook dokumentiert")

    lines.extend(["", "### Verifikation"])
    if verification:
        lines.extend(f"- {item}" for item in verification[:5])
    else:
        lines.append("- nicht im Runbook dokumentiert")

    return "\n".join(lines).strip()


def build_memory_context(query: str, profile: str, notes: list[dict[str, Any]]) -> str:
    context_notes = notes[:MAX_CONTEXT_NOTES]
    if context_notes and not any(note.get("_related") for note in context_notes):
        related_note = next((note for note in notes[MAX_CONTEXT_NOTES:] if note.get("_related")), None)
        if related_note:
            context_notes[-1] = related_note

    sections = [
        "Relevant notes retrieved from the Obsidian vault.",
        f"Recall profile: `{profile}`",
        "Freshness policy: prefer `fresh`, treat `review` cautiously, do not assume `warning` notes are safe to execute.",
        "",
    ]
    for index, note in enumerate(context_notes, start=1):
        frontmatter = note_frontmatter(note)
        metadata = note_metadata(note)
        path = str(note.get("path") or "")
        title = str(note.get("title") or path or f"Note {index}")
        kind = str(frontmatter.get("kind") or "note")
        updated = str(frontmatter.get("updated") or frontmatter.get("created") or "")
        freshness = note_freshness(note)
        flags = governance_flags(note)
        heading = str(note.get("heading_path") or note.get("heading") or "")
        snippet = compact_note_body(note, query)
        relation_line = ""
        if note.get("_related"):
            relation_bits = [
                str(note.get("_relation_direction") or "related"),
                str(note.get("_relation_type") or "related_to"),
                str(note.get("_related_anchor_path") or ""),
            ]
            relation_line = " ".join(bit for bit in relation_bits if bit).strip()
        sections.extend(
            [
                f"[{index}] {title}",
                f"- path: `{path}`",
                f"- kind: `{kind}`",
                f"- space: `{metadata.get('source_space', 'unknown')}` / class: `{metadata.get('knowledge_class', 'unknown')}` / source: `{metadata.get('source_type', 'unknown')}`",
                f"- section: `{heading or 'body'}` lines `{note.get('line_start', '?')}-{note.get('line_end', '?')}`",
                f"- updated: `{updated or 'unknown'}`",
                f"- freshness: `{freshness}`",
            ]
        )
        if relation_line:
            sections.append(f"- graph_relation: `{relation_line}`")
        if flags:
            sections.append(f"- warnings: `{', '.join(flags)}`")
        if snippet:
            sections.extend(["- snippet:", snippet, ""])
        else:
            sections.append("")
    return "\n".join(sections).strip()


def select_notes_for_context(ranked: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    selected_paths: set[str] = set()
    top_score: float | None = None

    for note in ranked:
        path = str(note.get("path") or "")
        if not path:
            continue
        note_score = float(note.get("_score") or 0.0)
        if top_score is None:
            top_score = note_score
        elif top_score - note_score > 80:
            continue
        kind = str(note_frontmatter(note).get("kind") or "").lower()
        if kind == "remediation-plan" and note_candidate_paths(note) & selected_paths:
            continue
        selected.append(note)
        selected_paths.add(path)
        if len(selected) >= MAX_MEMORY_NOTES:
            break
    return selected



async def get_query_embedding(query: str):
    """Get semantic embedding for query from BGE-M3 (node2, OpenAI-kompatibel)."""
    if not EMBED_API_URL or not query.strip():
        return None
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{EMBED_API_URL}/embeddings",
                json={"input": query[:1000], "model": EMBED_MODEL},
            )
            resp.raise_for_status()
            data = resp.json().get("data") or []
            return data[0].get("embedding") if data else None
    except Exception as exc:
        logging.debug("embed API unavailable: %s", exc)
        return None


async def get_batch_embeddings(texts):
    """Get embeddings for multiple texts in one call (BGE-M3, OpenAI-kompatibel)."""
    if not EMBED_API_URL or not texts:
        return None
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{EMBED_API_URL}/embeddings",
                json={"input": [t[:1000] for t in texts], "model": EMBED_MODEL},
            )
            resp.raise_for_status()
            items = sorted(resp.json().get("data", []), key=lambda d: d.get("index", 0))
            return [it.get("embedding") for it in items]
    except Exception as exc:
        logging.debug("embed batch API unavailable: %s", exc)
        return None


def cosine_similarity(a, b):
    """Cosine similarity between two float vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


async def semantic_rerank(notes, query, weight=0.35):
    """Blend cosine similarity into existing _score (in-place). No-ops gracefully."""
    if not notes:
        return
    texts = [
        (str(note.get("title") or "") + "\n" + str(note.get("content") or ""))[:800]
        for note in notes.values()
    ]
    try:
        query_emb, note_embs = await asyncio.gather(
            get_query_embedding(query),
            get_batch_embeddings(texts),
        )
    except Exception:
        return
    if query_emb is None or note_embs is None:
        return
    for note, note_emb in zip(notes.values(), note_embs):
        sim = cosine_similarity(query_emb, note_emb)
        note["_score"] = (1.0 - weight) * float(note.get("_score", 0.0)) + weight * sim


async def recall_context(query: str) -> tuple[str, str, list[dict[str, Any]]]:
    if not query:
        return "", "general", []

    profile = classify_query(query)
    plan = SEARCH_PLANS.get(profile, SEARCH_PLANS["general"])
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        search_tasks = [
            memory_search(
                client,
                query=query,
                limit=int(item.get("limit", SEARCH_CANDIDATE_LIMIT)),
                filters={key: value for key, value in item.items() if key != "limit"},
            )
            for item in plan
        ]
        aux_tasks: list[Any] = []
        if profile in {"ops", "security"}:
            aux_tasks.extend(
                [
                    memory_list(client, folder="memory/maintenance/reports", kind="maintenance-report", limit=1),
                    memory_list(client, folder="memory/maintenance/conflicts", kind="maintenance-conflict", limit=3),
                    memory_list(client, folder="memory/maintenance/reviews", kind="maintenance-review-backlog", limit=1),
                ]
            )
        raw_results = await asyncio.gather(*search_tasks, *aux_tasks, return_exceptions=True)

    merged: dict[str, dict[str, Any]] = {}
    order_index = 0
    for item in raw_results:
        if isinstance(item, Exception):
            logging.warning("memory search failed: %s", item)
            continue
        for note in item:
            path = str(note.get("path") or "")
            if not path:
                continue
            existing = merged.get(path)
            candidate = dict(note)
            candidate["_score"] = score_note(candidate, query, profile, order_index)
            order_index += 1
            if not existing or candidate["_score"] > existing["_score"]:
                merged[path] = candidate

    # Semantic reranking: blend cosine similarity (no-ops if embed service unavailable)
    await semantic_rerank(merged, query)

    ranked = sorted(merged.values(), key=lambda note: (-float(note["_score"]), str(note.get("path") or "")))
    selected = select_notes_for_context(ranked)
    if not selected:
        return "", profile, []
    return build_memory_context(query, profile, selected), profile, selected


def build_response_directive(profile: str, notes: list[dict[str, Any]]) -> str:
    if not notes:
        return ""
    primary = notes[0]
    primary_frontmatter = note_frontmatter(primary)
    primary_kind = str(primary_frontmatter.get("kind") or "").lower()
    if profile in {"ops", "security"} and len(notes) == 1 and primary_kind in {"runbook", "fix"}:
        approved_commands = primary_frontmatter.get("approved_commands")
        commands_line = "None documented."
        if isinstance(approved_commands, list) and approved_commands:
            commands_line = "; ".join(str(item) for item in approved_commands[:6])
        return (
            "Answer in German and stay strictly grounded in the retrieved runbook or fix. "
            "Use this structure exactly: `Kurzdiagnose`, `Schritte`, `Freigegebene Befehle`, `Nicht tun`, `Verifikation`. "
            "Under `Schritte`, keep the documented order and do not add new steps. "
            "Under `Freigegebene Befehle`, list only documented commands verbatim. "
            "If the note does not document something, say `nicht im Runbook dokumentiert`. "
            "Do not mention maintenance reports, follow-up documentation, or generic best practices unless the note explicitly says so. "
            f"Documented commands: {commands_line}"
        )
    if profile in {"ops", "security"}:
        return (
            "Answer in German, prefer the highest-ranked operational note, "
            "and do not invent commands or remediation steps that are not present in the retrieved notes."
        )
    return ""


def is_grounding_candidate(profile: str, notes: list[dict[str, Any]]) -> bool:
    if profile not in {"ops", "security"} or len(notes) != 1:
        return False
    note = notes[0]
    frontmatter = note_frontmatter(note)
    metadata = note_metadata(note)
    kind = str(frontmatter.get("kind") or "").lower()
    freshness = note_freshness(note)
    status = str(metadata.get("status") or "").lower()
    return kind in {"runbook", "fix"} and freshness == "fresh" and status in {"verified", "tested"}


def maybe_build_grounded_response(payload: dict[str, Any], profile: str, notes: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not is_grounding_candidate(profile, notes):
        return None
    note = notes[0]

    created = int(datetime.now(timezone.utc).timestamp())
    return {
        "id": f"chatcmpl-grounded-{created}",
        "object": "chat.completion",
        "created": created,
        "model": str(payload.get("model") or "memory-gateway"),
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": render_grounded_note_response(note),
                },
            }
        ],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
    }


def inject_memory(messages: list[dict[str, Any]], memory_context: str, profile: str, notes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    response_directive = build_response_directive(profile, notes)
    if not memory_context:
        return messages
    system_messages = [
        {
            "role": "system",
            "content": (
                "Relevant long-term memory was retrieved automatically. "
                "Use it only when it materially helps, cite uncertainty when the note looks stale, "
                "never propose unattended execution from notes marked `review` or `warning`, "
                "never prefer vault memory over the user's latest correction, "
                "and for runbooks or fixes prefer the documented steps and approved commands over generic advice.\n\n"
                f"{memory_context}"
            ),
        }
    ]
    if response_directive:
        system_messages.append({"role": "system", "content": response_directive})
    return [*system_messages, *messages]


def llm_api_url(path: str) -> str:
    normalized_path = "/" + path.lstrip("/")
    if LLM_BASE_URL.endswith("/v1") and normalized_path.startswith("/v1/"):
        normalized_path = normalized_path.removeprefix("/v1")
    return f"{LLM_BASE_URL}{normalized_path}"


def llm_health_url() -> str:
    if LLM_BASE_URL.endswith("/v1"):
        return f"{LLM_BASE_URL.removesuffix('/v1')}/health"
    return f"{LLM_BASE_URL}/health"


async def proxy_json(method: str, path: str, json_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        response = await client.request(method, llm_api_url(path), json=json_payload)
        response.raise_for_status()
        return response.json()


def build_memory_transcript(messages: list[dict[str, Any]], assistant_text: str) -> str:
    relevant_messages = messages[-AUTO_REMEMBER_LAST_MESSAGES:]
    parts: list[str] = []
    for message in relevant_messages:
        role = str(message.get("role") or "unknown").upper()
        text = extract_text(message.get("content"))
        if text:
            parts.append(f"{role}: {text}")
    if assistant_text:
        parts.append(f"ASSISTANT_FINAL: {assistant_text}")
    return "\n".join(parts).strip()


def should_attempt_auto_remember(query: str, assistant_text: str) -> bool:
    if not AUTO_REMEMBER_ENABLED:
        return False
    if len(query) + len(assistant_text) < AUTO_REMEMBER_MIN_CHARS:
        return False
    lowered = f"{query}\n{assistant_text}".lower()
    if any(greeting in lowered for greeting in {"hallo", "hello", "hi", "danke", "thanks"}) and len(lowered) < 220:
        return False
    return True


def extract_json_array(text: str) -> list[dict[str, Any]]:
    candidate = text.strip()
    fenced_match = re.search(r"```(?:json)?\s*(\[.*\])\s*```", candidate, flags=re.DOTALL)
    if fenced_match:
        candidate = fenced_match.group(1).strip()
    else:
        start = candidate.find("[")
        end = candidate.rfind("]")
        if start != -1 and end != -1 and start < end:
            candidate = candidate[start : end + 1]

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def sanitize_memory_item(raw: dict[str, Any]) -> dict[str, Any] | None:
    category = str(raw.get("category") or "").strip().lower()
    if category not in ALLOWED_MEMORY_CATEGORIES:
        return None
    if category not in AUTO_REMEMBER_ALLOWED_CATEGORIES:
        return None

    title = collapse_whitespace(str(raw.get("title") or ""))
    summary = collapse_whitespace(str(raw.get("summary") or ""))
    if not title or not summary:
        return None

    tags: list[str] = []
    for tag in raw.get("tags", []):
        if isinstance(tag, str):
            cleaned = slugify(tag)
            if cleaned and cleaned not in tags:
                tags.append(cleaned)

    steps: list[str] = []
    for step in raw.get("steps", []):
        if isinstance(step, str):
            cleaned = collapse_whitespace(step)
            if cleaned:
                steps.append(cleaned)

    joined_fields = "\n".join([title, summary, *steps, *tags])
    if any(pattern.search(joined_fields) for pattern in SECRET_PATTERNS):
        return None

    services = [
        slugify(service)
        for service in raw.get("services", [])
        if isinstance(service, str) and collapse_whitespace(service)
    ]
    hosts = [
        slugify(host)
        for host in raw.get("hosts", [])
        if isinstance(host, str) and collapse_whitespace(host)
    ]
    key = slugify(str(raw.get("key") or title))
    risk = str(raw.get("risk") or "unknown").strip().lower() or "unknown"
    if risk not in {"low", "medium", "high", "unknown"}:
        risk = "unknown"
    safe_to_auto_apply = False

    return {
        "category": category,
        "title": title[:160],
        "summary": summary[:1200],
        "tags": tags[:10],
        "steps": steps[:8],
        "services": services[:8],
        "hosts": hosts[:8],
        "key": key[:120],
        "risk": risk[:32],
        "safe_to_auto_apply": safe_to_auto_apply,
    }


def memory_note_path(item: dict[str, Any]) -> str:
    category = item["category"]
    key = item["key"]
    folders = {
        "fact": "memory/facts",
        "preference": "memory/preferences",
        "decision": "memory/decisions",
        "incident": "memory/incidents",
        "fix": "memory/fixes",
        "runbook": "memory/runbooks",
    }
    return f"{folders[category]}/{key}.md"


def render_memory_content(item: dict[str, Any], query: str, assistant_text: str) -> str:
    lines = [
        "# Dauerhaftes Wissen",
        "",
        "## Zusammenfassung",
        item["summary"],
        "",
    ]
    if item["steps"]:
        lines.append("## Schritte")
        for index, step in enumerate(item["steps"], start=1):
            lines.append(f"{index}. {step}")
        lines.append("")

    lines.extend(
        [
            "## Erfassungskontext",
            f"- Anfrage: `{query[:280]}`",
            f"- Auto-Anwendung erlaubt: `{str(item['safe_to_auto_apply']).lower()}`",
            f"- Risiko: `{item['risk']}`",
        ]
    )
    if item["services"]:
        lines.append(f"- Dienste: `{', '.join(item['services'])}`")
    if item["hosts"]:
        lines.append(f"- Hosts: `{', '.join(item['hosts'])}`")
    lines.extend(
        [
            "",
            "## Assistentenantwort",
            assistant_text[:1500],
            "",
        ]
    )
    return "\n".join(lines).strip() + "\n"


async def extract_memories(messages: list[dict[str, Any]], assistant_text: str, model: str | None) -> list[dict[str, Any]]:
    transcript = build_memory_transcript(messages, assistant_text)
    if not transcript:
        return []

    system_prompt = (
        "Extract only durable operational memory from the conversation. "
        "Keep facts that would help future IT operations or future answers. "
        "Allowed categories: fact, preference, decision, incident, fix, runbook. "
        "Ignore greetings, temporary tasks, generic explanations, secrets, tokens, passwords, and anything speculative. "
        "Return strict JSON only: a top-level array of objects with keys "
        "category, title, summary, tags, services, hosts, steps, risk, safe_to_auto_apply, key. "
        "Use an empty array if nothing should be stored."
    )
    user_prompt = (
        "Conversation transcript:\n"
        f"{transcript}\n\n"
        "Store only information that should still matter later."
    )

    payload: dict[str, Any] = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0,
        "max_tokens": AUTO_REMEMBER_MAX_TOKENS,
        "stream": False,
    }
    if model:
        payload["model"] = model

    response = await proxy_json("POST", "/v1/chat/completions", json_payload=payload)
    raw_text = latest_assistant_message(response)
    memories: list[dict[str, Any]] = []
    for item in extract_json_array(raw_text):
        sanitized = sanitize_memory_item(item)
        if sanitized:
            memories.append(sanitized)

    deduped: dict[str, dict[str, Any]] = {}
    for item in memories:
        deduped[item["key"]] = item
    return list(deduped.values())[:AUTO_REMEMBER_MAX_ITEMS]


async def persist_memories(items: list[dict[str, Any]], query: str, assistant_text: str) -> None:
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        for item in items:
            path = memory_note_path(item)
            extra_tags = ["needs-review"] if item["category"] in {"fix", "runbook"} else []
            tags = sorted(set([item["category"], "memory", *item["tags"], *item["services"], *item["hosts"], *extra_tags]))
            frontmatter: dict[str, Any] = {
                "kind": f"memory-{item['category']}" if item["category"] not in {"fix", "runbook", "incident"} else item["category"],
                "tags": tags,
                "risk": item["risk"],
                "safe_to_auto_apply": item["safe_to_auto_apply"],
                "requires_confirmation": item["category"] in {"fix", "runbook", "incident"},
                "services": item["services"],
                "hosts": item["hosts"],
                "captured_by": "memory-gateway",
                "schema_version": 1,
                "owner": "",
                "last_reviewed": "",
                "review_interval_days": 30,
                "review_status": "pending-review" if item["category"] in {"fix", "runbook"} else "captured",
            }
            response = await client.post(
                f"{MEMORY_API_URL}/upsert",
                headers=memory_headers(),
                json={
                    "path": path,
                    "title": item["title"],
                    "content": render_memory_content(item, query, assistant_text),
                    "tags": tags,
                    "frontmatter": frontmatter,
                    "append": False,
                },
            )
            response.raise_for_status()


async def auto_remember_conversation(
    messages: list[dict[str, Any]],
    query: str,
    assistant_text: str,
    model: str | None,
) -> None:
    try:
        memories = await extract_memories(messages=messages, assistant_text=assistant_text, model=model)
        if not memories:
            return
        await persist_memories(memories, query=query, assistant_text=assistant_text)
        logging.info("captured %s durable memories for query=%s", len(memories), query[:120])
    except Exception as exc:  # pragma: no cover - best-effort background work
        logging.warning("auto remember failed: %s", exc)


@app.get("/health")
async def health() -> dict[str, Any]:
    memory_ok = False
    llm_ok = False
    memory_status = ""
    llm_status = ""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                memory_resp = await client.get(f"{MEMORY_API_URL}/health")
                memory_ok = memory_resp.is_success
                memory_status = str(memory_resp.status_code)
            except httpx.HTTPError as exc:
                memory_status = type(exc).__name__
            try:
                llm_resp = await client.get(llm_health_url())
                llm_ok = llm_resp.is_success
                llm_status = str(llm_resp.status_code)
            except httpx.HTTPError as exc:
                llm_status = type(exc).__name__
    except httpx.HTTPError as exc:
        memory_status = memory_status or type(exc).__name__
        llm_status = llm_status or type(exc).__name__
    return {
        "status": "ok" if memory_ok and llm_ok else "degraded",
        "memory": memory_ok,
        "llm": llm_ok,
        "memory_api_url": MEMORY_API_URL,
        "llm_upstream": LLM_UPSTREAM_NAME,
        "llm_base_url": LLM_BASE_URL,
        "memory_status": memory_status,
        "llm_status": llm_status,
    }


@app.get("/livez")
async def livez() -> dict[str, str]:
    """Liveness: laeuft der Prozess. Kein Downstream-Ping (anders als /health)."""
    return {"status": "alive"}


@app.get("/v1/models")
async def models(_: None = Depends(require_gateway_auth)) -> dict[str, Any]:
    return await proxy_json("GET", "/v1/models")


@app.post("/v1/chat/completions")
async def chat_completions(request: Request, _: None = Depends(require_gateway_auth)) -> dict[str, Any]:
    payload = await request.json()
    if payload.get("stream"):
        raise HTTPException(status_code=501, detail="Streaming is not supported by the memory gateway.")

    messages = payload.get("messages")
    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="Payload must contain a messages list.")

    query = latest_user_message(messages)
    try:
        memory_context, profile, selected_notes = await recall_context(query)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Memory recall failed: {exc}") from exc

    grounded_notes = selected_notes
    if is_grounding_candidate(profile, selected_notes):
        note_path = str(selected_notes[0].get("path") or "")
        if note_path:
            try:
                async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                    full_note = await memory_get_note(client, path=note_path)
                if isinstance(full_note, dict):
                    full_note["_score"] = selected_notes[0].get("_score", 0.0)
                    grounded_notes = [full_note]
            except httpx.HTTPError:
                grounded_notes = selected_notes

    result = maybe_build_grounded_response(payload, profile, grounded_notes)
    if result is None:
        forwarded_payload = dict(payload)
        forwarded_payload["messages"] = inject_memory(messages, memory_context, profile, selected_notes)

        try:
            result = await proxy_json("POST", "/v1/chat/completions", json_payload=forwarded_payload)
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"LLM upstream failed: {type(exc).__name__}: {str(exc)}") from exc

    assistant_text = latest_assistant_message(result)
    if should_attempt_auto_remember(query, assistant_text):
        asyncio.create_task(
            auto_remember_conversation(
                messages=messages,
                query=query,
                assistant_text=assistant_text,
                model=str(payload.get("model") or "").strip() or None,
            )
        )

    result.setdefault("memory", {})
    result["memory"]["used"] = bool(memory_context)
    result["memory"]["query"] = query
    result["memory"]["profile"] = profile
    result["memory"]["notes"] = [
        {
            "path": note.get("path"),
            "title": note.get("title"),
            "score": round(float(note.get("_score", 0.0)), 2),
            "freshness": note_freshness(note),
            "flags": governance_flags(note),
        }
        for note in selected_notes[:MAX_CONTEXT_NOTES]
    ]
    result["memory"]["capture_scheduled"] = should_attempt_auto_remember(query, assistant_text)
    return result
