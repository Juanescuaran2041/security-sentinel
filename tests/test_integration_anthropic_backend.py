"""Test de integración — pipeline completo con AnthropicAdapter activo (API mockeada).

Escenario:
  Un diff con inyección SQL en app/db.py.

Pipeline completo:
  diff extraction → SAST (real, PatternEngine in-process) → CVE lookup → KB retrieval
  → LLM evaluation (AnthropicAdapter con API mockeada) → PR comment

Servicios mockeados:
  - DiffExtractionPort: AsyncMock (retorna diff crafteado)
  - CVELookupPort: AsyncMock (retorna vacío, no hay manifiestos relevantes)
  - KBRetrievalPort: AsyncMock (retorna fragmentos KB de SQL injection)
  - Anthropic Messages API: pytest-httpx (POST https://api.anthropic.com/v1/messages)
  - PRCommentPort: AsyncMock (captura la llamada)

Adaptadores REALES:
  - StaticAnalyzerMCPAdapter con PatternEngine (in-process)
  - AnthropicAdapter (con HTTP mockeado via pytest-httpx)

Verificaciones:
  - Pipeline completo se ejecuta con llm_backend="anthropic"
  - AnthropicAdapter llama correctamente a la API de Anthropic (mockeada)
  - SAST real detecta findings en el diff
  - LLM evalúa findings y produce veredictos correctos
  - AnalysisResult contiene confirmed findings con disposition adecuado
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
from pytest_httpx import HTTPXMock

from security_pr_guardian.adapters.llm.anthropic_adapter import AnthropicAdapter
from security_pr_guardian.adapters.mcp.static_analyzer_adapter import (
    StaticAnalyzerMCPAdapter,
)
from security_pr_guardian.core.agent import SecurityAgent
from security_pr_guardian.core.models import (
    AnalysisResult,
    AppConfig,
    KBFragment,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO = "org/secure-app"
PR_NUMBER = 15
ANTHROPIC_API_KEY = "sk-ant-fake-test-key"
ANTHROPIC_MODEL = "claude-3-sonnet-20240229"

# Diff con SQL injection (CWE-89)
DIFF_WITH_SQLI = """\
diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -1,3 +1,6 @@
 import sqlite3
+
+def get_user(user_id):
+    conn = sqlite3.connect("app.db")
+    query = f"SELECT * FROM users WHERE id = {user_id}"
+    return conn.execute(query).fetchone()
"""

# Respuesta JSON que el "LLM" devuelve confirmando explotabilidad
LLM_JSON_RESPONSE = json.dumps({
    "es_explotable": True,
    "severidad_ajustada": "high",
    "justificacion": (
        "El parámetro user_id se interpola directamente en la consulta SQL "
        "usando un f-string sin ninguna sanitización ni parametrización, "
        "permitiendo inyección SQL arbitraria por parte de un atacante."
    ),
    "recomendacion": {
        "descripcion": "Usar consultas parametrizadas con placeholders.",
        "codigo_corregido": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        "referencia": "https://cwe.mitre.org/data/definitions/89.html",
    },
})

# Respuesta completa de la API de Anthropic Messages
ANTHROPIC_API_RESPONSE = {
    "id": "msg_fake_test_id",
    "type": "message",
    "role": "assistant",
    "content": [{"type": "text", "text": LLM_JSON_RESPONSE}],
    "model": ANTHROPIC_MODEL,
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 600, "output_tokens": 250},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config() -> AppConfig:
    """AppConfig con backend anthropic."""
    return AppConfig(
        _env_file=None,
        github_token="ghp_integration_test_token",
        llm_backend="anthropic",
        anthropic_api_key=ANTHROPIC_API_KEY,
    )


def _make_kb_fragments() -> list[KBFragment]:
    """Fragmentos KB simulados para SQL injection."""
    return [
        KBFragment(
            titulo="CWE-89: SQL Injection",
            contenido=(
                "SQL Injection ocurre cuando el input del usuario se concatena "
                "directamente en consultas SQL sin parametrización. Esto permite "
                "a un atacante ejecutar comandos SQL arbitrarios."
            ),
            fuente="cwes/CWE-89.md",
            score_relevancia=0.92,
        ),
    ]


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_pipeline_with_anthropic_backend(httpx_mock: HTTPXMock):
    """
    DADO: Un diff con inyección SQL y config llm_backend="anthropic".
    CUANDO: Se ejecuta el pipeline completo del SecurityAgent.
    ENTONCES:
      - El AnthropicAdapter llama a POST https://api.anthropic.com/v1/messages.
      - El SAST real detecta la inyección SQL (CWE-89).
      - El LLM confirma el finding como explotable.
      - El AnalysisResult contiene confirmed findings con disposition="incluido".
    """
    config = _make_config()

    # Mock Anthropic Messages API — responde a todas las llamadas POST
    httpx_mock.add_response(
        method="POST",
        url="https://api.anthropic.com/v1/messages",
        json=ANTHROPIC_API_RESPONSE,
        status_code=200,
    )

    # Puerto diff: mock
    diff_port = AsyncMock()
    diff_port.get_diff.return_value = DIFF_WITH_SQLI

    # Puerto SAST: adaptador REAL con PatternEngine (in-process)
    static_port = StaticAnalyzerMCPAdapter()

    # Puerto CVE: mock (no hay manifiestos en este diff)
    cve_port = AsyncMock()
    cve_port.lookup_vulnerabilities.return_value = []

    # Puerto KB: mock con fragmentos de SQL injection
    kb_port = AsyncMock()
    kb_port.retrieve.return_value = _make_kb_fragments()

    # Puerto LLM: AnthropicAdapter REAL (HTTP mockeado por pytest-httpx)
    llm_port = AnthropicAdapter(api_key=ANTHROPIC_API_KEY, model=ANTHROPIC_MODEL)

    # Puerto PR Comment: mock
    comment_port = AsyncMock()
    comment_port.post_or_update_comment.return_value = "comment_99"

    # Construir el agente
    agent = SecurityAgent(
        config=config,
        diff_extraction_port=diff_port,
        static_analysis_port=static_port,
        cve_lookup_port=cve_port,
        kb_retrieval_port=kb_port,
        llm_reasoning_port=llm_port,
        pr_comment_port=comment_port,
    )

    # Ejecutar pipeline completo
    result = await agent.run(repo=REPO, pr_number=PR_NUMBER, dry_run=False)

    # --- Verificaciones ---

    # 1. El resultado es un AnalysisResult válido
    assert isinstance(result, AnalysisResult)
    assert result.repo == REPO
    assert result.pr_number == PR_NUMBER

    # 2. Hay confirmed findings
    assert len(result.confirmed_findings) > 0
    assert result.confirmed_count > 0

    # 3. El SAST real detectó SQL injection (CWE-89)
    sast_findings = [f for f in result.confirmed_findings if f.source == "static"]
    assert len(sast_findings) >= 1
    sql_injection_findings = [f for f in sast_findings if f.cwe_id == "CWE-89"]
    assert len(sql_injection_findings) >= 1, (
        "SAST debería detectar al menos un finding CWE-89 (SQL Injection)"
    )

    # 4. Todos los findings confirmados tienen disposition="incluido"
    for finding in result.confirmed_findings:
        assert finding.disposition == "incluido", (
            f"Finding {finding.finding_id} tiene disposition={finding.disposition}, "
            f"se esperaba 'incluido'"
        )

    # 5. El comment port fue llamado (no dry-run)
    comment_port.post_or_update_comment.assert_called_once()
    assert result.comment_id == "comment_99"

    # 6. Verificar que la API de Anthropic fue llamada
    anthropic_requests = [
        r for r in httpx_mock.get_requests()
        if "api.anthropic.com" in str(r.url)
    ]
    assert len(anthropic_requests) >= 1, (
        "El AnthropicAdapter debería hacer al menos una llamada a la API"
    )

    # 7. Verificar headers correctos en la request a Anthropic
    first_request = anthropic_requests[0]
    assert first_request.headers["x-api-key"] == ANTHROPIC_API_KEY
    assert first_request.headers["anthropic-version"] == "2023-06-01"
    assert first_request.headers["content-type"] == "application/json"

    # 8. Verificar payload correcto
    request_body = json.loads(first_request.content)
    assert request_body["model"] == ANTHROPIC_MODEL
    assert request_body["max_tokens"] == 2048
    assert "messages" in request_body
    assert request_body["messages"][0]["role"] == "user"
    assert "system" in request_body

    # 9. El diff port fue llamado correctamente
    diff_port.get_diff.assert_called_once_with(REPO, PR_NUMBER)

    # 10. KB retrieval fue llamado para cada candidato enviado al LLM
    assert kb_port.retrieve.call_count >= 1
