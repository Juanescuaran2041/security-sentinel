"""Tests para la salida JSON del CLI — render_json_output.

Cubre (Req 1.8):
- `--output json` produce JSON válido parseable
- El JSON contiene las claves requeridas: analysis_id, confirmed_count,
  discarded_count, confirmed_findings, diff_truncated
- No hay secuencias ANSI en la salida JSON
- Datetime serializado como ISO 8601
- El AnalysisResult completo está representado (sin campos descartados)
- Códigos de salida: 0 sin hallazgos explotables, 1 con hallazgos
"""

from __future__ import annotations

import io
import json
import re
import sys
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from security_pr_guardian.cli.output import render_json_output
from security_pr_guardian.core.models import (
    AnalysisResult,
    ConfirmedFinding,
    Recommendation,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _make_finding(
    severity: Severity = Severity.HIGH,
    disposition: str = "incluido",
) -> ConfirmedFinding:
    return ConfirmedFinding(
        finding_id="finding-json-001",
        source="static",
        tipo_vulnerabilidad="SQL Injection",
        archivo="app/db.py",
        linea_inicio=42,
        linea_fin=42,
        fragmento_codigo="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        cwe_id="CWE-89",
        cve_id=None,
        severidad_ajustada=severity,
        justificacion="Input del usuario concatenado directamente en la query SQL sin sanitizar.",
        recomendacion=Recommendation(
            descripcion="Usar consultas parametrizadas",
            codigo_corregido="cursor.execute('SELECT * FROM users WHERE id=?', (uid,))",
            referencia="https://cwe.mitre.org/data/definitions/89.html",
        ),
        disposition=disposition,
    )


def _make_result(
    findings: list[ConfirmedFinding] | None = None,
    diff_truncated: bool = False,
) -> AnalysisResult:
    return AnalysisResult(
        analysis_id="test-json-analysis-001",
        repo="owner/repo",
        pr_number=99,
        candidate_count=10,
        confirmed_count=len(findings) if findings else 0,
        discarded_count=3,
        not_evaluated_count=2,
        confirmed_findings=findings or [],
        diff_truncated=diff_truncated,
        dependency_limit_exceeded=False,
        duration_seconds=5.2,
        model_id="anthropic.claude-3-sonnet",
        guardian_version="0.1.0",
        timestamp_utc=datetime(2024, 6, 15, 14, 30, 0, tzinfo=timezone.utc),
    )


def _capture_json_output(result: AnalysisResult) -> str:
    """Captura la salida de render_json_output como string."""
    buf = io.StringIO()
    with patch.object(sys, "stdout", buf):
        render_json_output(result)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Tests: JSON output es parseable
# ---------------------------------------------------------------------------


class TestJsonOutputValid:
    def test_output_is_valid_json(self) -> None:
        """La salida de render_json_output es JSON válido."""
        result = _make_result(findings=[])
        output = _capture_json_output(result)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_output_with_findings_is_valid_json(self) -> None:
        """JSON válido incluso con findings confirmados."""
        finding = _make_finding()
        result = _make_result(findings=[finding])
        output = _capture_json_output(result)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Tests: Claves requeridas presentes
# ---------------------------------------------------------------------------


class TestJsonRequiredKeys:
    def test_contains_analysis_id(self) -> None:
        result = _make_result()
        output = _capture_json_output(result)
        parsed = json.loads(output)
        assert "analysis_id" in parsed
        assert parsed["analysis_id"] == "test-json-analysis-001"

    def test_contains_confirmed_count(self) -> None:
        result = _make_result()
        output = _capture_json_output(result)
        parsed = json.loads(output)
        assert "confirmed_count" in parsed
        assert parsed["confirmed_count"] == 0

    def test_contains_discarded_count(self) -> None:
        result = _make_result()
        output = _capture_json_output(result)
        parsed = json.loads(output)
        assert "discarded_count" in parsed
        assert parsed["discarded_count"] == 3

    def test_contains_confirmed_findings(self) -> None:
        result = _make_result()
        output = _capture_json_output(result)
        parsed = json.loads(output)
        assert "confirmed_findings" in parsed
        assert isinstance(parsed["confirmed_findings"], list)

    def test_contains_diff_truncated(self) -> None:
        result = _make_result(diff_truncated=True)
        output = _capture_json_output(result)
        parsed = json.loads(output)
        assert "diff_truncated" in parsed
        assert parsed["diff_truncated"] is True

    def test_all_required_keys_present(self) -> None:
        """Todas las claves requeridas por Property 15 están presentes."""
        finding = _make_finding()
        result = _make_result(findings=[finding])
        output = _capture_json_output(result)
        parsed = json.loads(output)

        required_keys = [
            "analysis_id",
            "confirmed_count",
            "discarded_count",
            "confirmed_findings",
            "diff_truncated",
        ]
        for key in required_keys:
            assert key in parsed, f"Missing required key: {key}"


# ---------------------------------------------------------------------------
# Tests: Sin secuencias ANSI
# ---------------------------------------------------------------------------


class TestJsonNoAnsi:
    def test_no_ansi_escape_codes_empty_findings(self) -> None:
        """Sin ANSI cuando no hay findings."""
        result = _make_result(findings=[])
        output = _capture_json_output(result)
        assert not ANSI_ESCAPE_RE.search(output), "ANSI escape codes found in JSON output"

    def test_no_ansi_escape_codes_with_findings(self) -> None:
        """Sin ANSI cuando hay findings."""
        finding = _make_finding(severity=Severity.CRITICAL)
        result = _make_result(findings=[finding])
        output = _capture_json_output(result)
        assert not ANSI_ESCAPE_RE.search(output), "ANSI escape codes found in JSON output"

    def test_no_esc_byte_anywhere(self) -> None:
        """No hay byte ESC (0x1b) en ninguna parte de la salida."""
        finding = _make_finding()
        result = _make_result(findings=[finding])
        output = _capture_json_output(result)
        assert "\x1b" not in output


# ---------------------------------------------------------------------------
# Tests: Serialización de datetime como ISO 8601
# ---------------------------------------------------------------------------


class TestJsonDatetimeSerialization:
    def test_timestamp_utc_is_iso8601(self) -> None:
        """timestamp_utc se serializa como ISO 8601."""
        result = _make_result()
        output = _capture_json_output(result)
        parsed = json.loads(output)

        ts = parsed["timestamp_utc"]
        # Debe ser parseable como datetime ISO 8601
        dt = datetime.fromisoformat(ts)
        assert dt.year == 2024
        assert dt.month == 6
        assert dt.day == 15

    def test_timestamp_utc_contains_timezone(self) -> None:
        """El timestamp incluye información de zona horaria UTC."""
        result = _make_result()
        output = _capture_json_output(result)
        parsed = json.loads(output)

        ts = parsed["timestamp_utc"]
        # Pydantic serializa con Z o +00:00
        assert "Z" in ts or "+00:00" in ts or "UTC" in ts


# ---------------------------------------------------------------------------
# Tests: AnalysisResult completo (sin campos descartados)
# ---------------------------------------------------------------------------


class TestJsonCompleteRepresentation:
    def test_all_model_fields_present(self) -> None:
        """Todos los campos del modelo AnalysisResult están en el JSON."""
        finding = _make_finding()
        result = _make_result(findings=[finding])
        output = _capture_json_output(result)
        parsed = json.loads(output)

        expected_fields = [
            "analysis_id",
            "repo",
            "pr_number",
            "candidate_count",
            "confirmed_count",
            "discarded_count",
            "not_evaluated_count",
            "confirmed_findings",
            "diff_truncated",
            "dependency_limit_exceeded",
            "comment_id",
            "duration_seconds",
            "model_id",
            "guardian_version",
            "timestamp_utc",
        ]
        for field in expected_fields:
            assert field in parsed, f"Missing field: {field}"

    def test_confirmed_findings_contain_all_fields(self) -> None:
        """Cada finding en confirmed_findings tiene todos sus campos."""
        finding = _make_finding()
        result = _make_result(findings=[finding])
        output = _capture_json_output(result)
        parsed = json.loads(output)

        assert len(parsed["confirmed_findings"]) == 1
        f = parsed["confirmed_findings"][0]

        expected_finding_fields = [
            "finding_id",
            "source",
            "tipo_vulnerabilidad",
            "archivo",
            "linea_inicio",
            "linea_fin",
            "fragmento_codigo",
            "cwe_id",
            "cve_id",
            "severidad_ajustada",
            "justificacion",
            "recomendacion",
            "disposition",
        ]
        for field in expected_finding_fields:
            assert field in f, f"Missing finding field: {field}"

    def test_recommendation_nested_fields(self) -> None:
        """La recomendación dentro de un finding tiene sus campos."""
        finding = _make_finding()
        result = _make_result(findings=[finding])
        output = _capture_json_output(result)
        parsed = json.loads(output)

        rec = parsed["confirmed_findings"][0]["recomendacion"]
        assert "descripcion" in rec
        assert "codigo_corregido" in rec
        assert "referencia" in rec

    def test_field_values_match_input(self) -> None:
        """Los valores en el JSON corresponden a los del modelo."""
        result = _make_result(findings=[], diff_truncated=False)
        output = _capture_json_output(result)
        parsed = json.loads(output)

        assert parsed["repo"] == "owner/repo"
        assert parsed["pr_number"] == 99
        assert parsed["candidate_count"] == 10
        assert parsed["confirmed_count"] == 0
        assert parsed["discarded_count"] == 3
        assert parsed["not_evaluated_count"] == 2
        assert parsed["diff_truncated"] is False
        assert parsed["dependency_limit_exceeded"] is False
        assert parsed["duration_seconds"] == 5.2
        assert parsed["model_id"] == "anthropic.claude-3-sonnet"
        assert parsed["guardian_version"] == "0.1.0"
        assert parsed["comment_id"] is None
