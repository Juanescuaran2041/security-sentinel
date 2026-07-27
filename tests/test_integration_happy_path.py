"""Test de integración end-to-end — Happy Path completo.

Escenario:
  Un diff que contiene:
    1. Una inyección SQL en app/db.py (detectada por PatternEngine / SAST real)
    2. Un cambio en requirements.txt que añade una dependencia vulnerable

  Pipeline completo:
    diff extraction → SAST (real) → CVE lookup → KB retrieval → LLM evaluation → PR comment

  Servicios externos mockeados:
    - DiffExtractionPort: AsyncMock (retorna diff crafteado)
    - CVELookupPort: AsyncMock (retorna CVEFinding para la dependencia vulnerable)
    - KBRetrievalPort: AsyncMock (retorna fragmentos KB relevantes)
    - LLMReasoningPort: AsyncMock (retorna es_explotable=True)
    - PRCommentPort: AsyncMock (captura la llamada con el resultado)

  Adaptador REAL:
    - StaticAnalyzerMCPAdapter con PatternEngine (in-process, sin HTTP)

  Verificaciones:
    - AnalysisResult contiene confirmed findings
    - SAST detecta SQL injection (CWE-89)
    - CVE finding está incluido
    - Todos los findings confirmados tienen disposition="incluido"
    - El PR comment port se llama con el AnalysisResult correcto
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from security_pr_guardian.adapters.mcp.static_analyzer_adapter import (
    StaticAnalyzerMCPAdapter,
)
from security_pr_guardian.core.agent import SecurityAgent
from security_pr_guardian.core.models import (
    AnalysisResult,
    AppConfig,
    CVEFinding,
    KBFragment,
    LLMVerdict,
    Recommendation,
    Severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

HAPPY_PATH_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 flask==2.3.0
+requests==2.25.0
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


def _make_cve_finding() -> CVEFinding:
    """CVEFinding simulado para requests==2.25.0."""
    return CVEFinding(
        cve_id="CVE-2023-32681",
        paquete="requests",
        version="2.25.0",
        ecosistema="PyPI",
        severidad="HIGH",
        descripcion="Unintended leak of Proxy-Authorization header in requests",
        referencias=["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"],
    )


def _make_kb_fragments() -> list[KBFragment]:
    """Fragmentos KB simulados para enriquecer el contexto del LLM."""
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


def _make_llm_verdict_exploitable() -> LLMVerdict:
    """Veredicto LLM que confirma que el finding es explotable."""
    return LLMVerdict(
        es_explotable=True,
        severidad_ajustada=Severity.HIGH,
        justificacion=(
            "El parámetro user_id se interpola directamente en la consulta SQL "
            "usando un f-string sin ninguna sanitización ni parametrización, "
            "permitiendo inyección SQL arbitraria por parte de un atacante."
        ),
        recomendacion=Recommendation(
            descripcion="Usar consultas parametrizadas con placeholders.",
            codigo_corregido='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            referencia="https://cwe.mitre.org/data/definitions/89.html",
        ),
    )


# ---------------------------------------------------------------------------
# Test de integración — Happy Path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_sql_injection_and_vulnerable_dependency():
    """
    DADO: Un diff con inyección SQL + una dependencia vulnerable en requirements.txt.
    CUANDO: Se ejecuta el pipeline completo del SecurityAgent.
    ENTONCES:
      - El SAST real detecta la inyección SQL (CWE-89).
      - El CVE lookup retorna la vulnerabilidad de requests.
      - El LLM confirma ambos findings como explotables.
      - El AnalysisResult contiene confirmed findings con disposition="incluido".
      - El PR comment port se llama con el resultado completo.
    """
    config = _make_config()

    # Puerto de diff: mock que retorna nuestro diff crafteado
    diff_port = AsyncMock()
    diff_port.get_diff.return_value = HAPPY_PATH_DIFF

    # Puerto SAST: adaptador REAL con PatternEngine (in-process)
    static_port = StaticAnalyzerMCPAdapter()

    # Puerto CVE: mock que retorna un CVEFinding para requests==2.25.0
    cve_port = AsyncMock()
    cve_port.lookup_vulnerabilities.return_value = [_make_cve_finding()]

    # Puerto KB: mock que retorna fragmentos relevantes
    kb_port = AsyncMock()
    kb_port.retrieve.return_value = _make_kb_fragments()

    # Puerto LLM: mock que siempre confirma como explotable
    llm_port = AsyncMock()
    llm_port.evaluate_finding.return_value = _make_llm_verdict_exploitable()

    # Puerto PR Comment: mock que captura la llamada
    comment_port = AsyncMock()
    comment_port.post_or_update_comment.return_value = "comment_42"

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
    result = await agent.run(repo="org/vulnerable-app", pr_number=7, dry_run=False)

    # --- Verificaciones ---

    # 1. El resultado es un AnalysisResult válido
    assert isinstance(result, AnalysisResult)
    assert result.repo == "org/vulnerable-app"
    assert result.pr_number == 7

    # 2. Hay confirmed findings
    assert len(result.confirmed_findings) > 0
    assert result.confirmed_count > 0

    # 3. El SAST real detectó SQL injection (CWE-89)
    sast_findings = [
        f for f in result.confirmed_findings if f.source == "static"
    ]
    assert len(sast_findings) >= 1
    sql_injection_findings = [
        f for f in sast_findings if f.cwe_id == "CWE-89"
    ]
    assert len(sql_injection_findings) >= 1, (
        "SAST debería detectar al menos un finding CWE-89 (SQL Injection)"
    )

    # 4. El CVE finding está incluido
    cve_findings = [
        f for f in result.confirmed_findings if f.source == "cve"
    ]
    assert len(cve_findings) >= 1
    assert any(f.cve_id == "CVE-2023-32681" for f in cve_findings)

    # 5. Todos los findings confirmados tienen disposition="incluido"
    #    (porque el LLM siempre retorna es_explotable=True)
    for finding in result.confirmed_findings:
        assert finding.disposition == "incluido", (
            f"Finding {finding.finding_id} tiene disposition={finding.disposition}, "
            f"se esperaba 'incluido'"
        )

    # 6. El comment port fue llamado (no dry-run)
    comment_port.post_or_update_comment.assert_called_once()
    call_args = comment_port.post_or_update_comment.call_args
    assert call_args[0][0] == "org/vulnerable-app"  # repo
    assert call_args[0][1] == 7  # pr_number
    # El tercer argumento es el AnalysisResult
    posted_result = call_args[0][2]
    assert isinstance(posted_result, AnalysisResult)
    assert posted_result.confirmed_count > 0

    # 7. El comment_id se refleja en el resultado
    assert result.comment_id == "comment_42"

    # 8. Contadores son coherentes
    assert result.candidate_count >= 2  # al menos 1 SAST + 1 CVE
    assert result.confirmed_count == len(
        [f for f in result.confirmed_findings if f.disposition == "incluido"]
    )
    assert result.discarded_count == 0
    assert result.not_evaluated_count == 0

    # 9. El diff port fue llamado correctamente
    diff_port.get_diff.assert_called_once_with("org/vulnerable-app", 7)

    # 10. CVE lookup fue llamado (porque hay manifest)
    cve_port.lookup_vulnerabilities.assert_called_once()

    # 11. KB retrieval fue llamado para cada candidato enviado al LLM
    assert kb_port.retrieve.call_count == llm_port.evaluate_finding.call_count

    # 12. LLM fue llamado para cada candidato (<=20)
    assert llm_port.evaluate_finding.call_count >= 2  # al menos SQL + CVE
