"""Test de integración E2E con servicios externos mockeados.

Escenario happy-path:
  Un diff con inyección SQL en app/db.py + requirements.txt añadiendo
  requests==2.25.0 (que tiene CVE-2023-32681).

Pipeline completo con adaptadores REALES y capas HTTP/AWS mockeadas:
  - GitHubDiffAdapter → pytest-httpx (GET diff)
  - StaticAnalyzerMCPAdapter → real, in-process (PatternEngine)
  - CVE lookup (OSV.dev) → pytest-httpx (POST querybatch)
  - BedrockAdapter → unittest.mock.patch (boto3 client.converse)
  - KBRetrievalPort → AsyncMock (ChromaDB es local pero requiere modelo)
  - GitHubPRCommenterAdapter → pytest-httpx (GET comments, POST comment)

Verificaciones:
  - AnalysisResult contiene findings confirmados con disposition="incluido"
  - SAST detecta SQL injection (CWE-89)
  - CVE finding de requests está incluido
  - PR comment se publica con watermark y contenido esperado
  - comment_id se refleja en el resultado
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from pytest_httpx import HTTPXMock

from security_pr_guardian.adapters.github.diff_adapter import GitHubDiffAdapter
from security_pr_guardian.adapters.github.pr_commenter import (
    GitHubPRCommenterAdapter,
    WATERMARK,
)
from security_pr_guardian.adapters.mcp.static_analyzer_adapter import (
    StaticAnalyzerMCPAdapter,
)
from security_pr_guardian.adapters.llm.bedrock_adapter import BedrockAdapter
from security_pr_guardian.core.agent import SecurityAgent
from security_pr_guardian.core.logger import StructuredLogger
from security_pr_guardian.core.models import (
    AnalysisResult,
    AppConfig,
    CVEFinding,
    DependencyChange,
    KBFragment,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO = "acme/webapp"
PR_NUMBER = 42
GITHUB_TOKEN = "ghp_fake_integration_test_token"
BEDROCK_REGION = "us-east-1"
BEDROCK_MODEL_ID = "anthropic.claude-3-sonnet-20240229-v1:0"

# Diff que contiene SQL injection + una dependencia vulnerable en requirements.txt
DIFF_WITH_SQLI_AND_VULN_DEP = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 flask==2.3.0
+requests==2.25.0
 pytest==7.4.0
diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -1,4 +1,10 @@
 import sqlite3
 
+
+def get_user(user_id):
+    conn = sqlite3.connect("app.db")
+    query = f"SELECT * FROM users WHERE id = {user_id}"
+    return conn.execute(query).fetchone()
+
+
 def healthcheck():
     return True
"""

# Respuesta OSV.dev para requests==2.25.0 con CVE-2023-32681
OSV_RESPONSE_REQUESTS = {
    "results": [
        {
            "vulns": [
                {
                    "id": "PYSEC-2023-74",
                    "aliases": ["CVE-2023-32681"],
                    "summary": "Unintended leak of Proxy-Authorization header in requests",
                    "severity": [{"score": "6.1"}],
                    "references": [
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"}
                    ],
                    "database_specific": {"severity": "MEDIUM"},
                }
            ]
        }
    ]
}

# Respuesta JSON del LLM que confirma explotabilidad
LLM_RESPONSE_EXPLOITABLE = json.dumps({
    "es_explotable": True,
    "severidad_ajustada": "high",
    "justificacion": (
        "El parámetro user_id se interpola directamente en la consulta SQL "
        "usando un f-string sin sanitización ni parametrización. Un atacante "
        "puede inyectar SQL arbitrario a través de este parámetro."
    ),
    "recomendacion": {
        "descripcion": "Usar consultas parametrizadas con placeholders en lugar de f-strings.",
        "codigo_corregido": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        "referencia": "https://cwe.mitre.org/data/definitions/89.html",
    },
})

# Estructura de respuesta Bedrock Converse API que envuelve el JSON del LLM
BEDROCK_CONVERSE_RESPONSE = {
    "output": {
        "message": {
            "role": "assistant",
            "content": [{"text": LLM_RESPONSE_EXPLOITABLE}],
        }
    },
    "stopReason": "end_turn",
    "usage": {"inputTokens": 500, "outputTokens": 200},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config() -> AppConfig:
    """AppConfig para el test de integración — backend bedrock."""
    return AppConfig(
        _env_file=None,
        github_token=GITHUB_TOKEN,
        llm_backend="bedrock",
        bedrock_region=BEDROCK_REGION,
        bedrock_model_id=BEDROCK_MODEL_ID,
    )


def _make_kb_fragments() -> list[KBFragment]:
    """Fragmentos KB de contexto para SQL injection."""
    return [
        KBFragment(
            titulo="CWE-89: Improper Neutralization of Special Elements in SQL",
            contenido=(
                "SQL Injection ocurre cuando se concatena o interpola input del "
                "usuario directamente en consultas SQL. Los atacantes pueden "
                "modificar la lógica de la consulta, extraer datos o ejecutar "
                "comandos administrativos."
            ),
            fuente="cwes/CWE-89.md",
            score_relevancia=0.91,
        ),
    ]


# ---------------------------------------------------------------------------
# CVE Lookup adapter que llama OSV.dev directamente vía httpx (sin MCP session)
# ---------------------------------------------------------------------------

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"


class DirectCVELookupAdapter:
    """Adaptador CVE que llama directamente a OSV.dev vía httpx.

    Replica la lógica esencial del servidor MCP cve_lookup_server sin
    importarlo (evita dependencia de mcp.server.fastmcp que puede no estar
    instalado en el entorno de test). Esto permite ejercitar las llamadas
    HTTP reales que pytest-httpx intercepta.
    """

    async def lookup_vulnerabilities(
        self, packages: list[DependencyChange]
    ) -> list[CVEFinding]:
        import httpx as _httpx

        results: list[CVEFinding] = []
        for dep in packages:
            if not dep.version or not dep.version.strip():
                continue

            payload = {
                "queries": [
                    {
                        "version": dep.version,
                        "package": {
                            "name": dep.package,
                            "ecosystem": dep.ecosystem,
                        },
                    }
                ]
            }

            async with _httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(OSV_QUERYBATCH_URL, json=payload)
                response.raise_for_status()
                data = response.json()

            osv_results = data.get("results", [])
            vulns: list[dict] = []
            if osv_results:
                vulns = osv_results[0].get("vulns", []) or []

            for vuln in vulns:
                cve_id = vuln.get("id", "UNKNOWN")
                for alias in vuln.get("aliases", []):
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break

                summary = vuln.get("summary") or vuln.get("details") or ""
                severity = self._map_severity(vuln)
                refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

                results.append(
                    CVEFinding(
                        cve_id=cve_id,
                        paquete=dep.package,
                        version=dep.version,
                        ecosistema=dep.ecosystem,
                        severidad=severity,
                        descripcion=summary[:500],
                        referencias=refs,
                    )
                )

        return results

    @staticmethod
    def _map_severity(vuln: dict) -> str:
        """Extrae severidad desde un objeto de vulnerabilidad OSV."""
        for entry in vuln.get("severity", []):
            score_str = entry.get("score", "")
            try:
                numeric = float(score_str)
                if numeric >= 9.0:
                    return "CRITICAL"
                elif numeric >= 7.0:
                    return "HIGH"
                elif numeric >= 4.0:
                    return "MEDIUM"
                elif numeric > 0.0:
                    return "LOW"
                else:
                    return "NONE"
            except ValueError:
                pass

        db_sev = vuln.get("database_specific", {}).get("severity", "")
        label_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
        if db_sev and db_sev.lower() in label_map:
            return label_map[db_sev.lower()]

        return "NONE"


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e2e_happy_path_sqli_and_vulnerable_dep_all_services_mocked(
    httpx_mock: HTTPXMock,
):
    """
    DADO: Un PR con diff que contiene SQL injection + dependencia vulnerable.
    CUANDO: Se ejecuta el pipeline completo con adaptadores reales y servicios
            externos mockeados (GitHub API vía pytest-httpx, OSV.dev vía
            pytest-httpx, Bedrock vía mock de boto3).
    ENTONCES:
      - El SAST real detecta la inyección SQL (CWE-89).
      - OSV.dev (mockeado) retorna CVE-2023-32681 para requests.
      - Bedrock (mockeado) confirma ambos findings como explotables.
      - El comentario del PR se publica vía GitHub API (mockeado).
      - El AnalysisResult refleja los findings confirmados.
    """
    config = _make_config()
    logger = StructuredLogger(analysis_id="test-e2e-001")

    # ------------------------------------------------------------------
    # Mock GitHub API: GET diff (retorna nuestro diff crafteado)
    # ------------------------------------------------------------------
    httpx_mock.add_response(
        method="GET",
        url=f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}",
        text=DIFF_WITH_SQLI_AND_VULN_DEP,
        status_code=200,
    )

    # ------------------------------------------------------------------
    # Mock GitHub API: GET existing comments (retorna vacío → no watermark)
    # ------------------------------------------------------------------
    httpx_mock.add_response(
        method="GET",
        url=f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments",
        json=[],
        status_code=200,
    )

    # ------------------------------------------------------------------
    # Mock GitHub API: POST nuevo comentario (retorna 201 con id)
    # ------------------------------------------------------------------
    httpx_mock.add_response(
        method="POST",
        url=f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments",
        json={"id": 98765, "body": "mocked"},
        status_code=201,
    )

    # ------------------------------------------------------------------
    # Mock OSV.dev: POST querybatch (retorna CVE para requests==2.25.0)
    # ------------------------------------------------------------------
    httpx_mock.add_response(
        method="POST",
        url="https://api.osv.dev/v1/querybatch",
        json=OSV_RESPONSE_REQUESTS,
        status_code=200,
    )

    # ------------------------------------------------------------------
    # Mock Bedrock (boto3 client) — patch a nivel de módulo en bedrock_adapter
    # ------------------------------------------------------------------
    mock_bedrock_client = MagicMock()
    mock_bedrock_client.converse.return_value = BEDROCK_CONVERSE_RESPONSE

    # ------------------------------------------------------------------
    # Ensamblar adaptadores reales
    # ------------------------------------------------------------------

    # Diff extraction: adaptador real (llamará GitHub API → interceptado por pytest-httpx)
    diff_adapter = GitHubDiffAdapter(
        token=GITHUB_TOKEN,
        logger=logger,
    )

    # SAST: adaptador real in-process con PatternEngine
    static_adapter = StaticAnalyzerMCPAdapter()

    # CVE lookup: adaptador directo que llama lookup_cve (usa httpx → interceptado)
    cve_adapter = DirectCVELookupAdapter()

    # KB: AsyncMock (ChromaDB requiere descarga de modelo pesado)
    kb_port = AsyncMock()
    kb_port.retrieve.return_value = _make_kb_fragments()

    # LLM: BedrockAdapter real con boto3 client mockeado
    with patch(
        "security_pr_guardian.adapters.llm.bedrock_adapter.boto3.client"
    ) as mock_boto3_client:
        mock_boto3_client.return_value = mock_bedrock_client

        llm_adapter = BedrockAdapter(
            region=BEDROCK_REGION,
            model_id=BEDROCK_MODEL_ID,
        )

    # PR Comment: adaptador real (llamará GitHub API → interceptado por pytest-httpx)
    comment_adapter = GitHubPRCommenterAdapter(
        token=GITHUB_TOKEN,
        logger=logger,
    )

    # ------------------------------------------------------------------
    # Construir SecurityAgent y ejecutar
    # ------------------------------------------------------------------
    agent = SecurityAgent(
        config=config,
        diff_extraction_port=diff_adapter,
        static_analysis_port=static_adapter,
        cve_lookup_port=cve_adapter,
        kb_retrieval_port=kb_port,
        llm_reasoning_port=llm_adapter,
        pr_comment_port=comment_adapter,
        logger=logger,
    )

    result = await agent.run(repo=REPO, pr_number=PR_NUMBER, dry_run=False)

    # ------------------------------------------------------------------
    # Assertions
    # ------------------------------------------------------------------

    # 1. El resultado es un AnalysisResult válido
    assert isinstance(result, AnalysisResult)
    assert result.repo == REPO
    assert result.pr_number == PR_NUMBER

    # 2. Hay confirmed findings
    assert result.confirmed_count > 0
    assert len(result.confirmed_findings) > 0

    # 3. SAST detectó SQL injection (CWE-89)
    sast_findings = [f for f in result.confirmed_findings if f.source == "static"]
    assert len(sast_findings) >= 1, "SAST debería detectar al menos un finding estático"
    sql_findings = [f for f in sast_findings if f.cwe_id == "CWE-89"]
    assert len(sql_findings) >= 1, (
        "SAST debería detectar CWE-89 (SQL Injection) en el f-string query"
    )

    # 4. CVE finding para requests está presente
    cve_findings = [f for f in result.confirmed_findings if f.source == "cve"]
    assert len(cve_findings) >= 1, "CVE lookup debería encontrar vulnerabilidad en requests"
    assert any(
        f.cve_id == "CVE-2023-32681" for f in cve_findings
    ), "CVE-2023-32681 debería estar entre los findings confirmados"

    # 5. Todos los findings tienen disposition="incluido" (LLM siempre retorna es_explotable=True)
    for finding in result.confirmed_findings:
        assert finding.disposition == "incluido", (
            f"Finding {finding.finding_id} tiene disposition={finding.disposition}, "
            f"se esperaba 'incluido' (mock LLM retorna es_explotable=True)"
        )

    # 6. PR comment fue publicado (comment_id asignado)
    assert result.comment_id == "98765"

    # 7. Contadores son coherentes
    assert result.candidate_count >= 2  # al menos 1 SAST + 1 CVE
    assert result.confirmed_count == len(
        [f for f in result.confirmed_findings if f.disposition == "incluido"]
    )
    assert result.discarded_count == 0
    assert result.not_evaluated_count == 0

    # 8. Duración es positiva
    assert result.duration_seconds > 0

    # 9. Model ID coincide con config
    assert result.model_id == BEDROCK_MODEL_ID

    # 10. Verificar que la GitHub API fue llamada correctamente
    requests_made = httpx_mock.get_requests()

    # Request de diff
    diff_requests = [
        r for r in requests_made
        if r.method == "GET" and "/pulls/" in str(r.url)
    ]
    assert len(diff_requests) == 1
    assert "application/vnd.github.v3.diff" in diff_requests[0].headers["accept"]

    # Request de creación de comentario
    comment_requests = [
        r for r in requests_made
        if r.method == "POST" and "/comments" in str(r.url)
    ]
    assert len(comment_requests) == 1
    comment_body = json.loads(comment_requests[0].content)["body"]
    # Verificar que el watermark está presente en el comentario
    assert WATERMARK in comment_body
    # Verificar que el comentario menciona SQL injection
    assert "sql" in comment_body.lower() or "SQL" in comment_body

    # 11. OSV.dev fue llamado
    osv_requests = [
        r for r in requests_made
        if "osv.dev" in str(r.url)
    ]
    assert len(osv_requests) >= 1
    osv_payload = json.loads(osv_requests[0].content)
    assert osv_payload["queries"][0]["package"]["name"] == "requests"
    assert osv_payload["queries"][0]["version"] == "2.25.0"

    # 12. Bedrock fue llamado para cada candidato
    assert mock_bedrock_client.converse.call_count >= 2  # SQL + CVE como mínimo

    # 13. KB retrieval fue llamado para cada candidato enviado al LLM
    assert kb_port.retrieve.call_count == mock_bedrock_client.converse.call_count
