"""Tests unitarios del renderizado de la plantilla Jinja2 (Tarea 7.4).

Casos a cubrir:
  1. Secciones obligatorias presentes en el comentario renderizado.
  2. Hallazgos ordenados por severidad descendente en la tabla.
  3. Mensaje de no-vulnerabilidades correcto cuando confirmed_findings está vacío.
  4. Bloque de advertencia de truncación visible cuando diff_truncated=True.

Estrategia:
  - No se necesita httpx ni mocks de red — solo se renderiza la plantilla
    con datos de prueba y se verifica el string resultante.
  - Se usa el método _render_comment() del adaptador directamente.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from security_pr_guardian.adapters.github.pr_commenter import (
    WATERMARK,
    GitHubPRCommenterAdapter,
)
from security_pr_guardian.core.models import (
    AnalysisResult,
    ConfirmedFinding,
    Recommendation,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO = "owner/repo"
PR_NUMBER = 42


def make_finding(
    severity: Severity,
    disposition: str = "incluido",
    tipo: str = "SQL Injection",
    archivo: str = "app/db.py",
    linea: int = 10,
    cwe_id: str = "CWE-89",
) -> ConfirmedFinding:
    """Crea un ConfirmedFinding con la severidad y disposition indicadas."""
    return ConfirmedFinding(
        finding_id=f"test-{severity.value}",
        source="static",
        tipo_vulnerabilidad=tipo,
        archivo=archivo,
        linea_inicio=linea,
        linea_fin=linea,
        fragmento_codigo=f"fragmento de codigo vulnerable para {severity.value}",
        cwe_id=cwe_id,
        severidad_ajustada=severity,
        justificacion=(
            f"Este hallazgo de severidad {severity.value} es explotable porque "
            "el input del usuario llega sin sanitizar directamente al componente vulnerable."
        ),
        recomendacion=Recommendation(
            descripcion=f"Corregir la vulnerabilidad de {severity.value}.",
            codigo_corregido="# codigo corregido aqui",
            referencia=cwe_id,
        ),
        disposition=disposition,
    )


def make_result(
    findings: list[ConfirmedFinding],
    diff_truncated: bool = False,
    candidate_count: int = 5,
    discarded_count: int = 2,
    timestamp: datetime | None = None,
) -> AnalysisResult:
    """Crea un AnalysisResult con los datos de prueba."""
    if timestamp is None:
        timestamp = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

    return AnalysisResult(
        repo=REPO,
        pr_number=PR_NUMBER,
        candidate_count=candidate_count,
        confirmed_count=len([f for f in findings if f.disposition == "incluido"]),
        discarded_count=discarded_count,
        not_evaluated_count=len([f for f in findings if f.disposition == "no_evaluado"]),
        confirmed_findings=findings,
        diff_truncated=diff_truncated,
        dependency_limit_exceeded=False,
        duration_seconds=3.7,
        model_id="anthropic.claude-3-sonnet",
        guardian_version="0.1.0",
        timestamp_utc=timestamp,
    )


def make_adapter() -> GitHubPRCommenterAdapter:
    """Crea un adaptador listo para tests (sin analysis_result en el constructor)."""
    return GitHubPRCommenterAdapter(token="ghp_test", logger=None)


# ---------------------------------------------------------------------------
# Test 1: Secciones obligatorias presentes
# ---------------------------------------------------------------------------


def test_mandatory_sections_present():
    """
    DADO: Un AnalysisResult con al menos un finding confirmado.
    CUANDO: se renderiza la plantilla.
    ENTONCES: el comentario contiene todas las secciones obligatorias.
    """
    adapter = make_adapter()
    result = make_result([make_finding(Severity.HIGH)])
    output = adapter._render_comment(result)

    assert WATERMARK in output
    assert "Resumen Ejecutivo" in output
    assert "Tabla de Hallazgos" in output
    assert "Detalle de Hallazgos" in output
    assert "Security PR Guardian v" in output
    assert "Duración:" in output


# ---------------------------------------------------------------------------
# Test 2: Orden descendente de severidad en la tabla
# ---------------------------------------------------------------------------


def test_findings_ordered_by_severity_descending():
    """
    DADO: Findings con severidades CRITICAL, MEDIUM, LOW (en ese orden en la lista).
    CUANDO: se renderiza la plantilla.
    ENTONCES: en el output, CRITICAL aparece antes que MEDIUM, y MEDIUM antes que LOW.
    """
    findings = [
        make_finding(Severity.CRITICAL, tipo="Injection Critical", linea=1),
        make_finding(Severity.MEDIUM, tipo="Injection Medium", linea=2),
        make_finding(Severity.LOW, tipo="Injection Low", linea=3),
    ]
    adapter = make_adapter()
    result = make_result(findings)
    output = adapter._render_comment(result)

    assert output.index("CRITICAL") < output.index("MEDIUM") < output.index("LOW")


# ---------------------------------------------------------------------------
# Test 3: Mensaje de no-vulnerabilidades
# ---------------------------------------------------------------------------


def test_no_vulnerabilities_message_when_no_findings():
    """
    DADO: Un AnalysisResult con confirmed_findings vacío.
    CUANDO: se renderiza la plantilla.
    ENTONCES:
      - Aparece el mensaje de no vulnerabilidades.
      - Aparecen los conteos de candidatos y descartados.
      - Aparece el timestamp en formato ISO 8601 UTC.
      - NO aparece la tabla de hallazgos.
    """
    adapter = make_adapter()
    result = make_result(findings=[], candidate_count=5, discarded_count=5)
    output = adapter._render_comment(result)

    assert "Sin Vulnerabilidades Detectadas" in output
    assert "Tabla de Hallazgos" not in output
    assert "2024-01-15T10:30:00Z" in output
    # candidate_count and discarded_count both equal 5
    assert "5" in output


# ---------------------------------------------------------------------------
# Test 4: Advertencia de truncación
# ---------------------------------------------------------------------------


def test_truncation_warning_visible_when_diff_truncated():
    """
    DADO: Un AnalysisResult con diff_truncated=True.
    CUANDO: se renderiza la plantilla.
    ENTONCES: el bloque de advertencia de truncación aparece en el output.
    """
    adapter = make_adapter()

    result_truncated = make_result(
        findings=[make_finding(Severity.LOW)],
        diff_truncated=True,
    )
    output_truncated = adapter._render_comment(result_truncated)
    assert "Advertencia: diff truncado" in output_truncated

    result_not_truncated = make_result(
        findings=[make_finding(Severity.LOW)],
        diff_truncated=False,
    )
    output_not_truncated = adapter._render_comment(result_not_truncated)
    assert "Advertencia: diff truncado" not in output_not_truncated
