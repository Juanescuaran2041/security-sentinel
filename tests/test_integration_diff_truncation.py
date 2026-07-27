"""Test de integración — Truncación de diff: diff con más de 10 000 líneas.

Escenario:
  Un diff con ~10200 líneas añadidas de datos bulk, seguido de patrones
  de vulnerabilidad (SQL injection, OS command injection) DESPUÉS de la
  línea 10 000.

  Pipeline:
    diff extraction → DiffParser (trunca) → SAST (real) → CVE → KB → LLM → PR comment

  Verificaciones:
    - result.diff_truncated == True
    - El comentario renderizado contiene la advertencia de truncación
      ("⚠️", "diff truncado", "10.000 líneas")
    - No hay findings (CandidateFinding ni ConfirmedFinding) con
      linea_inicio > 10000, porque el diff fue truncado antes del análisis

  Servicios externos mockeados:
    - DiffExtractionPort: AsyncMock (retorna contenido de large_pr.diff)
    - CVELookupPort: AsyncMock (sin CVEs)
    - KBRetrievalPort: AsyncMock (retorna fragmentos KB)
    - LLMReasoningPort: AsyncMock (retorna es_explotable=True)
    - PRCommentPort: AsyncMock (captura la llamada)

  Adaptador REAL:
    - StaticAnalyzerMCPAdapter con PatternEngine (in-process, sin HTTP)
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
    LLMVerdict,
    Recommendation,
    Severity,
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_TEMPLATES_DIR = Path(__file__).parent.parent / "security_pr_guardian" / "templates"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config() -> AppConfig:
    """AppConfig válido sin leer .env ni variables de entorno del sistema."""
    return AppConfig(
        _env_file=None,
        github_token="ghp_integration_test_token",
        llm_backend="bedrock",
        bedrock_region="us-east-1",
        bedrock_model_id="anthropic.claude-3-sonnet-20240229-v1:0",
        max_diff_lines=10000,
    )


def _make_kb_fragments() -> list[KBFragment]:
    """Fragmentos KB simulados."""
    return [
        KBFragment(
            titulo="CWE-89: SQL Injection",
            contenido=(
                "SQL Injection ocurre cuando el input del usuario se concatena "
                "directamente en consultas SQL sin parametrización."
            ),
            fuente="OWASP/CWE",
            score_relevancia=0.90,
        ),
    ]


def _make_llm_verdict_exploitable() -> LLMVerdict:
    """Veredicto LLM que confirma que un finding es explotable."""
    return LLMVerdict(
        es_explotable=True,
        severidad_ajustada=Severity.HIGH,
        justificacion=(
            "El parámetro se interpola directamente en la consulta SQL "
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
# Test de integración — Truncación de diff
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_diff_truncation_large_pr():
    """
    DADO: Un diff (large_pr.diff) con ~10200+ líneas añadidas y patrones
          de vulnerabilidad DESPUÉS de la línea 10 000.
    CUANDO: Se ejecuta el pipeline completo del SecurityAgent con max_diff_lines=10000.
    ENTONCES:
      - result.diff_truncated == True.
      - El comentario renderizado contiene la advertencia de truncación.
      - No hay findings con linea_inicio > 10000 (las vulnerabilidades
        del segundo archivo NO se detectan porque están más allá del corte).
    """
    config = _make_config()

    # Leer el fixture large_pr.diff desde disco
    large_diff_content = (_FIXTURES_DIR / "large_pr.diff").read_text(encoding="utf-8")

    # Puerto de diff: mock que retorna el contenido del fixture
    diff_port = AsyncMock()
    diff_port.get_diff.return_value = large_diff_content

    # Puerto SAST: adaptador REAL con PatternEngine (in-process)
    static_port = StaticAnalyzerMCPAdapter()

    # Puerto CVE: mock sin hallazgos
    cve_port = AsyncMock()
    cve_port.lookup_vulnerabilities.return_value = []

    # Puerto KB: mock que retorna fragmentos relevantes
    kb_port = AsyncMock()
    kb_port.retrieve.return_value = _make_kb_fragments()

    # Puerto LLM: mock que siempre confirma como explotable
    # (si hay findings dentro del límite, serán confirmados)
    llm_port = AsyncMock()
    llm_port.evaluate_finding.return_value = _make_llm_verdict_exploitable()

    # Puerto PR Comment: mock que captura la llamada
    comment_port = AsyncMock()
    comment_port.post_or_update_comment.return_value = "comment_truncated_01"

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

    # Ejecutar pipeline completo (dry_run=True para simplificar)
    result = await agent.run(repo="org/large-pr-app", pr_number=42, dry_run=True)

    # --- Verificaciones ---

    # 1. El resultado es un AnalysisResult válido
    assert isinstance(result, AnalysisResult)
    assert result.repo == "org/large-pr-app"
    assert result.pr_number == 42

    # 2. El diff fue truncado
    assert result.diff_truncated is True, (
        "El diff tiene más de 10000 líneas añadidas, diff_truncated debe ser True"
    )

    # 3. No hay findings con linea_inicio > 10000
    #    (las vulnerabilidades en app/legacy/reports.py están después del corte)
    for finding in result.confirmed_findings:
        assert finding.linea_inicio <= 10000, (
            f"Finding {finding.finding_id} tiene linea_inicio={finding.linea_inicio} "
            f"que excede el límite de truncación (10000). "
            f"Archivo: {finding.archivo}, tipo: {finding.tipo_vulnerabilidad}"
        )

    # 4. Verificar que las vulnerabilidades del segundo archivo (reports.py)
    #    NO fueron detectadas (están más allá de la línea 10000)
    reports_findings = [
        f for f in result.confirmed_findings
        if "reports" in f.archivo
    ]
    assert len(reports_findings) == 0, (
        "No debería haber findings de app/legacy/reports.py porque "
        "están más allá de la línea 10000 (zona truncada)"
    )

    # 5. Renderizar la plantilla y verificar presencia de advertencia de truncación
    jinja_env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=False,
    )
    template = jinja_env.get_template("pr_comment.md.j2")
    rendered_comment = template.render(result=result)

    # 5a. Debe contener el emoji de advertencia
    assert "⚠️" in rendered_comment, (
        "El comentario del PR debe contener la advertencia ⚠️ por truncación"
    )

    # 5b. Debe contener "diff truncado"
    assert "diff truncado" in rendered_comment.lower(), (
        "El comentario del PR debe contener 'diff truncado'"
    )

    # 5c. Debe contener referencia a "10.000 líneas"
    assert "10.000" in rendered_comment, (
        "El comentario del PR debe mencionar el límite de '10.000 líneas'"
    )

    # 6. El diff port fue llamado correctamente
    diff_port.get_diff.assert_called_once_with("org/large-pr-app", 42)
