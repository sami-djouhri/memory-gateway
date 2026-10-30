from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
except ModuleNotFoundError:
    fastapi_stub = types.ModuleType("fastapi")

    class FastAPIStub:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def get(self, *args: object, **kwargs: object):
            return lambda func: func

        def post(self, *args: object, **kwargs: object):
            return lambda func: func

    class HTTPExceptionStub(Exception):
        def __init__(self, status_code: int, detail: str) -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    def default_value(default: object = None, **kwargs: object) -> object:
        return default

    fastapi_stub.Depends = default_value
    fastapi_stub.FastAPI = FastAPIStub
    fastapi_stub.Header = default_value
    fastapi_stub.HTTPException = HTTPExceptionStub
    fastapi_stub.Request = object
    fastapi_stub.status = types.SimpleNamespace(HTTP_401_UNAUTHORIZED=401)
    sys.modules["fastapi"] = fastapi_stub

    httpx_stub = types.ModuleType("httpx")

    class HTTPErrorStub(Exception):
        pass

    class AsyncClientStub:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

    httpx_stub.HTTPError = HTTPErrorStub
    httpx_stub.AsyncClient = AsyncClientStub
    sys.modules["httpx"] = httpx_stub

from app import app as gateway_app  # noqa: E402


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self.payload


class FakeClient:
    def __init__(self, payload: dict):
        self.payload = payload
        self.posts: list[dict] = []

    async def post(self, url: str, *, headers: dict, json: dict) -> FakeResponse:
        self.posts.append({"url": url, "headers": headers, "json": json})
        return FakeResponse(self.payload)


class GatewayRagTests(unittest.IsolatedAsyncioTestCase):
    def test_default_llm_upstream_is_node2(self) -> None:
        self.assertEqual(gateway_app.LLM_UPSTREAM_NAME, "node2")
        self.assertEqual(gateway_app.DEFAULT_LLM_BASE_URL, "http://192.0.2.10:8081")

    def test_llm_api_url_accepts_root_or_v1_base(self) -> None:
        original_base = gateway_app.LLM_BASE_URL
        try:
            gateway_app.LLM_BASE_URL = "http://192.0.2.10:8081"
            self.assertEqual(
                gateway_app.llm_api_url("/v1/chat/completions"),
                "http://192.0.2.10:8081/v1/chat/completions",
            )
            self.assertEqual(gateway_app.llm_health_url(), "http://192.0.2.10:8081/health")

            gateway_app.LLM_BASE_URL = "http://192.0.2.10:8081/v1"
            self.assertEqual(
                gateway_app.llm_api_url("/v1/chat/completions"),
                "http://192.0.2.10:8081/v1/chat/completions",
            )
            self.assertEqual(gateway_app.llm_health_url(), "http://192.0.2.10:8081/health")
        finally:
            gateway_app.LLM_BASE_URL = original_base

    def test_ops_search_plan_includes_ops_events_vault_space(self) -> None:
        ops_spaces = {
            str(item.get("source_space"))
            for item in gateway_app.SEARCH_PLANS["ops"]
            if item.get("source_space")
        }
        security_spaces = {
            str(item.get("source_space"))
            for item in gateway_app.SEARCH_PLANS["security"]
            if item.get("source_space")
        }

        self.assertIn("ops_events", ops_spaces)
        self.assertIn("ops_events", security_spaces)

    async def test_memory_search_includes_related_graph_notes(self) -> None:
        client = FakeClient(
            {
                "results": [
                    {
                        "path": "homelab/runbooks/docker.md",
                        "title": "Docker Runbook",
                        "frontmatter": {"kind": "runbook"},
                        "metadata": {"source_space": "homelab"},
                    }
                ],
                "related": [
                    {
                        "path": "homelab/services/docker.md",
                        "title": "Docker Service",
                        "frontmatter": {"kind": "service-note"},
                        "metadata": {"source_space": "homelab"},
                        "anchor_path": "homelab/runbooks/docker.md",
                        "relation_type": "depends_on",
                        "relation_direction": "outgoing",
                    }
                ],
            }
        )

        notes = await gateway_app.memory_search(client, "docker status", limit=4, filters={"rag_include": True})

        self.assertEqual([note["path"] for note in notes], ["homelab/runbooks/docker.md", "homelab/services/docker.md"])
        self.assertTrue(notes[1]["_related"])
        self.assertEqual(notes[1]["_related_anchor_path"], "homelab/runbooks/docker.md")
        self.assertEqual(client.posts[0]["json"]["include_related"], True)
        self.assertEqual(client.posts[0]["json"]["related_limit"], gateway_app.MEMORY_RELATED_LIMIT)

    def test_memory_context_marks_graph_related_notes(self) -> None:
        context = gateway_app.build_memory_context(
            "docker status",
            "ops",
            [
                {
                    "path": "homelab/services/docker.md",
                    "title": "Docker Service",
                    "frontmatter": {"kind": "service-note"},
                    "metadata": {"source_space": "homelab", "knowledge_class": "evergreen_knowledge"},
                    "excerpt": "Docker service context",
                    "_related": True,
                    "_related_anchor_path": "homelab/runbooks/docker.md",
                    "_relation_type": "depends_on",
                    "_relation_direction": "outgoing",
                }
            ],
        )

        self.assertIn("graph_relation", context)
        self.assertIn("outgoing depends_on homelab/runbooks/docker.md", context)

    def test_memory_context_reserves_slot_for_graph_related_note(self) -> None:
        original_max_context = gateway_app.MAX_CONTEXT_NOTES
        try:
            gateway_app.MAX_CONTEXT_NOTES = 3
            notes = [
                {
                    "path": f"homelab/direct-{index}.md",
                    "title": f"Direct {index}",
                    "frontmatter": {"kind": "note"},
                    "metadata": {"source_space": "homelab", "knowledge_class": "operational_knowledge"},
                    "excerpt": "Direct context",
                }
                for index in range(3)
            ]
            notes.append(
                {
                    "path": "homelab/related.md",
                    "title": "Related",
                    "frontmatter": {"kind": "service-note"},
                    "metadata": {"source_space": "homelab", "knowledge_class": "evergreen_knowledge"},
                    "excerpt": "Related context",
                    "_related": True,
                    "_related_anchor_path": "homelab/direct-0.md",
                    "_relation_type": "depends_on",
                    "_relation_direction": "incoming",
                }
            )

            context = gateway_app.build_memory_context("docker status", "ops", notes)

            self.assertIn("graph_relation", context)
            self.assertIn("homelab/related.md", context)
            self.assertNotIn("homelab/direct-2.md", context)
        finally:
            gateway_app.MAX_CONTEXT_NOTES = original_max_context


if __name__ == "__main__":
    unittest.main()
