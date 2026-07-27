"""Test de integración — CVE analysis omitido cuando no hay manifiestos en el diff.

Escenario:
  Un diff que contiene SOLO código fuente Python con una vulnerabilidad
  (command injection via os.system) pero SIN cambios en archivos de manifiesto
  de dependencias (package.json, requirements.txt, Pipfile, pyproject.toml, etc.)

  Pipeline:
    diff extraction → SAST (real) → [CVE lookup OMITIDO] → KB retrieval → LLM → PR comment

  Servicios externos mockeados:
    - DiffExtractionPort: AsyncMock (retorna diff sin manifiestos)
    - CVELookupPort: AsyncMock (NO debe ser llamado)
    - KBRetrievalPort: AsyncMock (retorna fragmentos KB)
    - LLMReasoningPort: AsyncMock (confirma finding como explotable)
    - PRCommentPort: AsyncMock (captura la llamada)

  Adaptador REAL:
    - StaticAnalyzerMCPAdapter con PatternEngine (in-process, sin HTTP)

  Verificaciones:
    - CVELookupPort.lookup_vulnerabilities NUNCA es llamado
    - SAST detecta command injection (CWE-78)
    - LLM es llamado para evaluar el finding SAST
    - AnalysisResult es válido, sin CVE findings
    - El pipeline funciona end-to-end correctamente
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
    KBFragment,
    LLMVerdict,
    Recommendation,
    Severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

NO_MANIFEST_DIFF = """\
diff --git a/app/views.py b/app/views.py
--- a/app/views.py
+++ b/app/views.py
@@ -1,3 +1,6 @@
 import os
+
+def run_cmd(user_input):
+    os.system(f"echo {user_input}")
+    return "done"
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
    """Fragmentos KB simulados para command injection."""
    return [
        KBFragment(
            titulo="CWE-78: OS Command Injection",
            contenido=(
                "OS Command Injection ocurre cuando el input del usuario se "
                "concatena directamente en comandos del sistema operativo sin "
                "sanitización. Esto permite a un atacante ejecutar comandos "
                "arbitrarios en el servidor."
            ),
            fuente="OWASP/CWE",
            score_relevancia=0.90,
        ),
    ]


def _make_llm_verdict_exploitable() -> LLMVerdict:
    """Veredicto LLM que confirma que el finding es explotable."""
    return LLMVerdict(
        es_explotable=True,
        severidad_ajustada=Severity.HIGH,
        justificacion=(
            "El parámetro user_input se interpola directamente en os.system() "
            "usando un f-string sin ninguna sanitización, permitiendo inyección "
            "de comandos arbitrarios por parte de un atacante."
        ),
        recomendacion=Recommendation(
            descripcion="Usar subprocess con lista de argumentos en lugar de os.system.",
            codigo_corregido='subprocess.run(["echo", user_input], check=True)',
            referencia="https://cwe.mitre.org/data/definitions/78.html",
        ),
    )


# ---------------------------------------------------------------------------
# Test de integración — Sin manifiestos, CVE omitido
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_manifests_skips_cve_lookup():
    """
    DADO: Un diff con solo código fuente (command injection) y SIN manifiestos.
    CUANDO: Se ejecuta el pipeline completo del SecurityAgent.
    ENTONCES:
      - CVELookupPort.lookup_vulnerabilities NUNCA es llamado.
      - El SAST real detecta la command injection (CWE-78).
      - El LLM es llamado para evaluar el finding.
      - El AnalysisResult no contiene CVE findings.
      - El pipeline funciona end-to-end correctamente.
    """
    config = _make_config()

    # Puerto de diff: mock que retorna nuestro diff sin manifiestos
    diff_port = AsyncMock()
    diff_port.get_diff.return_value = NO_MANIFEST_DIFF

    # Puerto SAST: adaptador REAL con PatternEngine (in-process)
    static_port = StaticAnalyzerMCPAdapter()

    # Puerto CVE: mock que NO debe ser llamado
    cve_port = AsyncMock()
    cve_port.lookup_vulnerabilities.return_value = []

    # Puerto KB: mock que retorna fragmentos relevantes
    kb_port = AsyncMock()
    kb_port.retrieve.return_value = _make_kb_fragments()

    # Puerto LLM: mock que confirma como explotable
    llm_port = AsyncMock()
    llm_port.evaluate_finding.return_value = _make_llm_verdict_exploitable()

    # Puerto PR Comment: mock que captura la llamada
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
    result = await agent.run(repo="org/source-only-app", pr_number=42, dry_run=False)

    # --- Verificaciones ---

    # 1. CVE lookup NUNCA fue llamado (no hay manifiestos)
    cve_port.lookup_vulnerabilities.assert_not_called()

    # 2. El resultado es un AnalysisResult válido
    assert isinstance(result, AnalysisResult)
    assert result.repo == "org/source-only-app"
    assert result.pr_number == 42

    # 3. SAST detectó al menos un finding (command injection CWE-78)
    assert result.candidate_count >= 1
    sast_findings = [f for f in result.confirmed_findings if f.source == "static"]
    assert len(sast_findings) >= 1
    cmd_injection_findings = [f for f in sast_findings if f.cwe_id == "CWE-78"]
    assert len(cmd_injection_findings) >= 1, (
        "SAST debería detectar al menos un finding CWE-78 (Command Injection)"
    )

    # 4. No hay CVE findings en el resultado
    cve_findings_in_result = [f for f in result.confirmed_findings if f.source == "cve"]
    assert len(cve_findings_in_result) == 0

    # 5. LLM fue llamado para evaluar los findings SAST
    assert llm_port.evaluate_finding.call_count >= 1

    # 6. KB retrieval fue llamado para cada candidato enviado al LLM
    assert kb_port.retrieve.call_count == llm_port.evaluate_finding.call_count

    # 7. Confirmed findings tienen disposition="incluido" (LLM confirma)
    for finding in result.confirmed_findings:
        assert finding.disposition == "incluido"

    # 8. Contadores son coherentes
    assert result.confirmed_count == len(
        [f for f in result.confirmed_findings if f.disposition == "incluido"]
    )
    assert result.dependency_limit_exceeded is False

    # 9. El comment port fue llamado (no dry-run)
    comment_port.post_or_update_comment.assert_called_once()
    call_args = comment_port.post_or_update_comment.call_args
    assert call_args[0][0] == "org/source-only-app"
    assert call_args[0][1] == 42
    posted_result = call_args[0][2]
    assert isinstance(posted_result, AnalysisResult)

    # 10. El comment_id se refleja en el resultado
    assert result.comment_id == "comment_99"
