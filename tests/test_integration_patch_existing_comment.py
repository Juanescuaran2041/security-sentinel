"""Test de integración — comentario PR existente con marca de agua.

Escenario:
  GitHub API retorna un comentario existente con la marca de agua
  `<!-- security-pr-guardian -->` → el adaptador usa PATCH en lugar de POST
  para actualizar el comentario.

Pipeline completo con adaptadores REALES y capas HTTP/AWS mockeadas:
  - GitHubDiffAdapter → pytest-httpx (GET diff)
  - StaticAnalyzerMCPAdapter → real, in-process (PatternEngine)
  - CVE lookup → omitido (no hay manifiestos en el diff)
  - BedrockAdapter → unittest.mock.patch (boto3 client.converse)
  - KBRetrievalPort → AsyncMock
  - GitHubPRCommenterAdapter → pytest-httpx (GET comments con watermark, PATCH comment)

Verificaciones:
  - No se hace POST al endpoint de comentarios
  - Se hace PATCH a /repos/{owner}/{repo}/issues/comments/12345
  - El cuerpo del PATCH contiene la marca de agua
  - result.comment_id == "12345"
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
EXISTING_COMMENT_ID = 12345

# Diff simple con SQL injection (sin manifiestos → CVE lookup se omite)
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

# Respuesta JSON del LLM que confirma explotabilidad
LLM_RESPONSE = json.dumps({
    "es_explotable": True,
    "severidad_ajustada": "high",
    "justificacion": "SQL injection via f-string interpolation",
    "recomendacion": {
        "descripcion": "Use parameterized queries",
        "codigo_corregido": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        "referencia": "https://cwe.mitre.org/data/definitions/89.html",
    },
})

BEDROCK_CONVERSE_RESPONSE = {
    "output": {"message": {"role": "assistant", "content": [{"text": LLM_RESPONSE}]}},
    "stopReason": "end_turn",
    "usage": {"inputTokens": 500, "outputTokens": 200},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config() -> AppConfig:
    return AppConfig(
        _env_file=None,
        github_token=GITHUB_TOKEN,
        llm_backend="bedrock",
        bedrock_region=BEDROCK_REGION,
        bedrock_model_id=BEDROCK_MODEL_ID,
    )


def _make_kb_fragments() -> list[KBFragment]:
    return [
        KBFragment(
            titulo="CWE-89: SQL Injection",
            contenido="SQL Injection ocurre cuando se interpola input del usuario en queries SQL.",
            fuente="cwes/CWE-89.md",
            score_relevancia=0.91,
        ),
    ]


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_existing_comment_when_watermark_found(
    httpx_mock: HTTPXMock,
):
    """
    DADO: Un PR con un comentario existente que contiene la marca de agua.
    CUANDO: Se ejecuta el pipeline completo (dry_run=False).
    ENTONCES:
      - El adaptador hace PATCH (no POST) al comentario existente.
      - El comment_id del resultado coincide con el del comentario existente.
      - El cuerpo del PATCH contiene la marca de agua.
    """
    config = _make_config()
    logger = StructuredLogger(analysis_id="test-patch-comment-001")

    # ------------------------------------------------------------------
    # Mock GitHub API: GET diff
    # ------------------------------------------------------------------
    httpx_mock.add_response(
        method="GET",
        url=f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}",
        text=DIFF_WITH_SQLI,
        status_code=200,
    )

    # ------------------------------------------------------------------
    # Mock GitHub API: GET comments → retorna comentario con watermark
    # ------------------------------------------------------------------
    existing_comments = [
        {"id": 11111, "body": "Some unrelated comment from a reviewer."},
        {
            "id": EXISTING_COMMENT_ID,
            "body": f"{WATERMARK}\n## Security Analysis\nPrevious analysis results...",
        },
        {"id": 22222, "body": "LGTM!"},
    ]
    httpx_mock.add_response(
        method="GET",
        url=f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments",
        json=existing_comments,
        status_code=200,
    )

    # ------------------------------------------------------------------
    # Mock GitHub API: PATCH comment (actualizar el existente)
    # ------------------------------------------------------------------
    httpx_mock.add_response(
        method="PATCH",
        url=f"https://api.github.com/repos/{REPO}/issues/comments/{EXISTING_COMMENT_ID}",
        json={"id": EXISTING_COMMENT_ID, "body": "updated"},
        status_code=200,
    )

    # ------------------------------------------------------------------
    # Mock Bedrock (boto3 client)
    # ------------------------------------------------------------------
    mock_bedrock_client = MagicMock()
    mock_bedrock_client.converse.return_value = BEDROCK_CONVERSE_RESPONSE

    # ------------------------------------------------------------------
    # Ensamblar adaptadores
    # ------------------------------------------------------------------
    diff_adapter = GitHubDiffAdapter(token=GITHUB_TOKEN, logger=logger)
    static_adapter = StaticAnalyzerMCPAdapter()

    # CVE lookup: AsyncMock que retorna vacío (no hay manifiestos)
    cve_port = AsyncMock()
    cve_port.lookup_vulnerabilities.return_value = []

    # KB: AsyncMock
    kb_port = AsyncMock()
    kb_port.retrieve.return_value = _make_kb_fragments()

    # LLM: BedrockAdapter con boto3 mockeado
    with patch(
        "security_pr_guardian.adapters.llm.bedrock_adapter.boto3.client"
    ) as mock_boto3_client:
        mock_boto3_client.return_value = mock_bedrock_client
        llm_adapter = BedrockAdapter(region=BEDROCK_REGION, model_id=BEDROCK_MODEL_ID)

    # PR Comment: adaptador real (pytest-httpx intercepta)
    comment_adapter = GitHubPRCommenterAdapter(token=GITHUB_TOKEN, logger=logger)

    # ------------------------------------------------------------------
    # Construir SecurityAgent y ejecutar
    # ------------------------------------------------------------------
    agent = SecurityAgent(
        config=config,
        diff_extraction_port=diff_adapter,
        static_analysis_port=static_adapter,
        cve_lookup_port=cve_port,
        kb_retrieval_port=kb_port,
        llm_reasoning_port=llm_adapter,
        pr_comment_port=comment_adapter,
        logger=logger,
    )

    result = await agent.run(repo=REPO, pr_number=PR_NUMBER, dry_run=False)

    # ------------------------------------------------------------------
    # Assertions
    # ------------------------------------------------------------------

    # 1. El resultado es válido
    assert isinstance(result, AnalysisResult)
    assert result.repo == REPO
    assert result.pr_number == PR_NUMBER

    # 2. comment_id coincide con el comentario existente
    assert result.comment_id == str(EXISTING_COMMENT_ID)

    # 3. Verificar las requests HTTP realizadas
    requests_made = httpx_mock.get_requests()

    # NO debe haber POST a comments
    post_comment_requests = [
        r for r in requests_made
        if r.method == "POST" and "/comments" in str(r.url)
    ]
    assert len(post_comment_requests) == 0, (
        "No debería haber POST — el comentario existente debe actualizarse con PATCH"
    )

    # Debe haber PATCH al comment_id correcto
    patch_requests = [
        r for r in requests_made
        if r.method == "PATCH" and f"/issues/comments/{EXISTING_COMMENT_ID}" in str(r.url)
    ]
    assert len(patch_requests) == 1, (
        f"Debería haber exactamente un PATCH a /issues/comments/{EXISTING_COMMENT_ID}"
    )

    # 4. El body del PATCH contiene la marca de agua
    patch_body = json.loads(patch_requests[0].content)["body"]
    assert WATERMARK in patch_body, (
        "El cuerpo del PATCH debe contener la marca de agua del agente"
    )
