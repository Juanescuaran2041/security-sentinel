"""Test de integración — Throttling de Bedrock: no_evaluado con advertencia visible.

Escenario:
  Un diff que contiene una inyección SQL. El LLM (Bedrock) sufre ThrottlingException
  repetida y, tras agotar reintentos, el agente NO puede evaluar el finding.
  El finding queda marcado con disposition="no_evaluado" y el comentario del PR
  muestra la advertencia ⚠️ de revisión manual.

  Pipeline:
    diff extraction → SAST (real) → CVE lookup → KB retrieval → LLM (FALLA) → PR comment

  Servicios externos mockeados:
    - DiffExtractionPort: AsyncMock (retorna diff crafteado con SQL injection)
    - CVELookupPort: AsyncMock (sin CVEs)
    - KBRetrievalPort: AsyncMock (retorna fragmentos KB)
    - LLMReasoningPort: AsyncMock (LANZA RuntimeError simulando throttling agotado)
    - PRCommentPort: AsyncMock (captura la llamada para verificar el comentario)

  Adaptador REAL:
    - StaticAnalyzerMCPAdapter con PatternEngine (in-process, sin HTTP)

  Verificaciones:
    - result.not_evaluated_count >= 1
    - Existen findings con disposition="no_evaluado"
    - El comentario renderizado contiene "No evaluado" y la advertencia ⚠️
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from jinja2 import Environment, FileSystemLoader

from security_pr_guardian.adapters.mcp.static_analyzer_adapter import (
    StaticAnalyzerMCPAdapter,
)
from security_pr_guardian.core.agent import SecurityAgent
from security_pr_guardian.core.models import (
    AnalysisResult,
    AppConfig,
    KBFragment,
    Severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

THROTTLING_DIFF = """\
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


def _make_config() -> AppConfig:
    """AppConfig válido sin leer .env ni variables de entorno del sistema."""
    return AppConfig(
        _env_file=None,
        github_token="ghp_integration_test_token",
        llm_backend="bedrock",
        bedrock_region="us-east-1",
        bedrock_model_id="anthropic.claude-3-sonnet-20240229-v1:0",
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
            fuente="OWASP/CWE",
            score_relevancia=0.92,
        ),
    ]


# Directorio de templates para renderizar el comentario del PR
_TEMPLATES_DIR = Path(__file__).parent.parent / "security_pr_guardian" / "templates"


# ---------------------------------------------------------------------------
# Test de integración — Throttling de Bedrock → no_evaluado
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_throttling_produces_no_evaluado_with_warning():
    """
    DADO: Un diff con inyección SQL y un LLM que lanza RuntimeError
          (simulando ThrottlingException con reintentos agotados).
    CUANDO: Se ejecuta el pipeline completo del SecurityAgent.
    ENTONCES:
      - El finding queda con disposition="no_evaluado".
      - result.not_evaluated_count >= 1.
      - El comentario del PR contiene "No evaluado" y la advertencia ⚠️.
    """
    config = _make_config()

    # Puerto de diff: mock que retorna diff con SQL injection
    diff_port = AsyncMock()
    diff_port.get_diff.return_value = THROTTLING_DIFF

    # Puerto SAST: adaptador REAL con PatternEngine (in-process)
    static_port = StaticAnalyzerMCPAdapter()

    # Puerto CVE: mock sin hallazgos (no hay manifiestos)
    cve_port = AsyncMock()
    cve_port.lookup_vulnerabilities.return_value = []

    # Puerto KB: mock que retorna fragmentos relevantes
    kb_port = AsyncMock()
    kb_port.retrieve.return_value = _make_kb_fragments()

    # Puerto LLM: mock que SIEMPRE lanza RuntimeError
    # Simula throttling agotado (3 reintentos fallidos en Bedrock)
    llm_port = AsyncMock()
    llm_port.evaluate_finding.side_effect = RuntimeError(
        "ThrottlingException: reintentos agotados tras 3 intentos"
    )

    # Puerto PR Comment: mock que captura la llamada
    comment_port = AsyncMock()
    comment_port.post_or_update_comment.return_value = "comment_throttled_01"

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

    # Ejecutar pipeline completo (no dry-run → PR comment se publica)
    result = await agent.run(repo="org/throttled-app", pr_number=99, dry_run=False)

    # --- Verificaciones ---

    # 1. El resultado es un AnalysisResult válido
    assert isinstance(result, AnalysisResult)
    assert result.repo == "org/throttled-app"
    assert result.pr_number == 99

    # 2. Hay findings no evaluados
    assert result.not_evaluated_count >= 1, (
        f"Se esperaba al menos 1 finding no_evaluado, "
        f"pero not_evaluated_count={result.not_evaluated_count}"
    )

    # 3. Existen findings con disposition="no_evaluado"
    no_evaluado_findings = [
        f for f in result.confirmed_findings if f.disposition == "no_evaluado"
    ]
    assert len(no_evaluado_findings) >= 1, (
        "Debe haber al menos un finding con disposition='no_evaluado'"
    )

    # 4. Ningún finding tiene disposition="incluido" (LLM nunca respondió)
    incluidos = [f for f in result.confirmed_findings if f.disposition == "incluido"]
    assert len(incluidos) == 0, (
        "No debería haber findings incluidos cuando el LLM falla por throttling"
    )

    # 5. confirmed_count debe ser 0 (ninguno fue confirmado como explotable)
    assert result.confirmed_count == 0

    # 6. El comment port fue llamado
    comment_port.post_or_update_comment.assert_called_once()
    call_args = comment_port.post_or_update_comment.call_args
    assert call_args[0][0] == "org/throttled-app"
    assert call_args[0][1] == 99
    posted_result = call_args[0][2]
    assert isinstance(posted_result, AnalysisResult)
    assert posted_result.not_evaluated_count >= 1

    # 7. El comment_id se refleja en el resultado
    assert result.comment_id == "comment_throttled_01"

    # 8. Verificar que el LLM fue llamado (al menos 1 vez)
    assert llm_port.evaluate_finding.call_count >= 1

    # 9. Los findings no_evaluado conservan la severidad inicial
    for finding in no_evaluado_findings:
        assert finding.severidad_ajustada is not None

    # 10. La justificación menciona el fallo del LLM
    for finding in no_evaluado_findings:
        assert "No evaluado" in finding.justificacion or "LLM" in finding.justificacion

    # --- Verificar el contenido del comentario renderizado ---

    # 11. Renderizar la plantilla con el resultado y verificar advertencia visible
    jinja_env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=False,
    )
    template = jinja_env.get_template("pr_comment.md.j2")
    rendered_comment = template.render(result=result)

    # El comentario debe contener la sección "No evaluado"
    assert "No evaluado" in rendered_comment, (
        "El comentario del PR debe contener 'No evaluado'"
    )

    # El comentario debe contener la advertencia ⚠️
    assert "⚠️" in rendered_comment, (
        "El comentario del PR debe contener la advertencia ⚠️"
    )

    # El comentario debe contener la recomendación de revisión manual
    assert "revisión manual" in rendered_comment.lower() or "revision manual" in rendered_comment.lower(), (
        "El comentario debe recomendar revisión manual para findings no evaluados"
    )
