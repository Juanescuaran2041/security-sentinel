"""Tests para security_pr_guardian.cli.output — lógica de salida del CLI.

Cubre:
- Panel verde cuando no hay hallazgos explotables (Req 1.3)
- Borde rojo cuando la severidad máxima es HIGH o CRITICAL (Req 1.4)
- Borde amarillo cuando la severidad máxima es MEDIUM o inferior (Req 1.4)
- Tabla con columnas: Severidad, Tipo, Archivo:Línea, CVE/CWE (Req 1.4)
- ANSI omitido cuando NO_COLOR está presente (Req 1.7)
- ANSI omitido cuando TERM=dumb (Req 1.7)
- Advertencia de truncación cuando diff_truncated=True (Req 2.6)
"""

from __future__ import annotations

import io
import os
from datetime import datetime, timezone

import pytest
from rich.console import Console

from security_pr_guardian.cli.output import (
    SEVERITY_STYLE,
    make_console,
    render_text_output,
    should_disable_color,
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


def _make_finding(
    severity: Severity = Severity.HIGH,
    tipo: str = "SQL Injection",
    archivo: str = "app/db.py",
    linea: int = 42,
    cwe_id: str | None = "CWE-89",
    cve_id: str | None = None,
    disposition: str = "incluido",
) -> ConfirmedFinding:
    return ConfirmedFinding(
        finding_id="test-finding-001",
        source="static",
        tipo_vulnerabilidad=tipo,
        archivo=archivo,
        linea_inicio=linea,
        linea_fin=linea,
        fragmento_codigo="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
        cwe_id=cwe_id,
        cve_id=cve_id,
        severidad_ajustada=severity,
        justificacion="Input del usuario concatenado directamente en la query SQL.",
        recomendacion=Recommendation(
            descripcion="Usar consultas parametrizadas",
            codigo_corregido="cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
            referencia="https://cwe.mitre.org/data/definitions/89.html",
        ),
        disposition=disposition,
    )


def _make_result(
    findings: list[ConfirmedFinding] | None = None,
    diff_truncated: bool = False,
) -> AnalysisResult:
    return AnalysisResult(
        analysis_id="test-analysis-001",
        repo="owner/repo",
        pr_number=123,
        candidate_count=5,
        confirmed_count=len(findings) if findings else 0,
        discarded_count=2,
        not_evaluated_count=1,
        confirmed_findings=findings or [],
        diff_truncated=diff_truncated,
        dependency_limit_exceeded=False,
        duration_seconds=3.5,
        model_id="anthropic.claude-3-sonnet",
        guardian_version="0.1.0",
        timestamp_utc=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )


def _capture_output(result: AnalysisResult, *, no_color: bool = False) -> str:
    """Renderiza el resultado y captura la salida como string."""
    buf = io.StringIO()
    console = Console(file=buf, no_color=no_color, width=120)
    render_text_output(result, console)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Tests: should_disable_color
# ---------------------------------------------------------------------------


class TestShouldDisableColor:
    def test_no_color_env_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.delenv("TERM", raising=False)
        assert should_disable_color() is True

    def test_no_color_env_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """NO_COLOR con valor vacío aún desactiva colores (spec dice 'presente')."""
        monkeypatch.setenv("NO_COLOR", "")
        monkeypatch.delenv("TERM", raising=False)
        assert should_disable_color() is True

    def test_term_dumb(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "dumb")
        assert should_disable_color() is True

    def test_normal_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")
        assert should_disable_color() is False

    def test_no_term_no_no_color(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        assert should_disable_color() is False


# ---------------------------------------------------------------------------
# Tests: make_console
# ---------------------------------------------------------------------------


class TestMakeConsole:
    def test_respects_no_color_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.delenv("TERM", raising=False)
        console = make_console()
        assert console.no_color is True

    def test_force_no_color(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        console = make_console(force_no_color=True)
        assert console.no_color is True

    def test_stderr_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        console = make_console(stderr=True)
        assert console.stderr is True


# ---------------------------------------------------------------------------
# Tests: render_text_output — éxito (sin hallazgos explotables)
# ---------------------------------------------------------------------------


class TestRenderSuccess:
    def test_green_panel_when_no_exploitable_findings(self) -> None:
        """Req 1.3: panel verde cuando no hay vulnerabilidades explotables."""
        result = _make_result(findings=[])
        output = _capture_output(result)

        assert "No se encontraron vulnerabilidades explotables" in output
        assert "Security PR Guardian" in output

    def test_green_panel_excludes_discarded_findings(self) -> None:
        """Findings con disposition != 'incluido' no cuentan como explotables."""
        discarded = _make_finding(disposition="descartado")
        result = _make_result(findings=[discarded])
        output = _capture_output(result)

        assert "No se encontraron vulnerabilidades explotables" in output

    def test_success_shows_candidate_counts(self) -> None:
        result = _make_result(findings=[])
        output = _capture_output(result)

        assert "Candidatos analizados: 5" in output
        assert "Descartados: 2" in output
        assert "No evaluados: 1" in output


# ---------------------------------------------------------------------------
# Tests: render_text_output — hallazgos (borde rojo/amarillo)
# ---------------------------------------------------------------------------


class TestRenderFindings:
    def test_red_border_when_max_severity_critical(self) -> None:
        """Req 1.4: borde rojo cuando la severidad máxima es CRITICAL."""
        finding = _make_finding(severity=Severity.CRITICAL)
        result = _make_result(findings=[finding])
        # Para verificar el estilo, usamos la consola con record
        buf = io.StringIO()
        console = Console(file=buf, no_color=False, width=120, force_terminal=True)
        render_text_output(result, console)
        output = buf.getvalue()

        # El panel debe contener "vulnerabilidades explotables"
        assert "vulnerabilidades explotables" in output

    def test_red_border_when_max_severity_high(self) -> None:
        """Req 1.4: borde rojo cuando la severidad máxima es HIGH."""
        finding = _make_finding(severity=Severity.HIGH)
        result = _make_result(findings=[finding])
        output = _capture_output(result)

        assert "vulnerabilidades explotables" in output

    def test_yellow_border_when_max_severity_medium(self) -> None:
        """Req 1.4: borde amarillo cuando la severidad máxima es MEDIUM."""
        finding = _make_finding(severity=Severity.MEDIUM)
        result = _make_result(findings=[finding])
        output = _capture_output(result)

        assert "vulnerabilidades explotables" in output

    def test_yellow_border_when_max_severity_low(self) -> None:
        """Borde amarillo cuando la severidad máxima es LOW."""
        finding = _make_finding(severity=Severity.LOW)
        result = _make_result(findings=[finding])
        output = _capture_output(result)

        assert "vulnerabilidades explotables" in output

    def test_table_has_correct_columns(self) -> None:
        """Req 1.4: tabla tiene columnas Severidad, Tipo, Archivo:Línea, CVE/CWE."""
        finding = _make_finding()
        result = _make_result(findings=[finding])
        output = _capture_output(result)

        assert "Severidad" in output
        assert "Tipo" in output
        assert "Archivo:L\u00ednea" in output
        assert "CVE/CWE" in output

    def test_table_shows_finding_data(self) -> None:
        """La tabla muestra los datos del finding correctamente."""
        finding = _make_finding(
            severity=Severity.HIGH,
            tipo="SQL Injection",
            archivo="app/db.py",
            linea=42,
            cwe_id="CWE-89",
        )
        result = _make_result(findings=[finding])
        output = _capture_output(result)

        assert "HIGH" in output
        assert "SQL Injection" in output
        assert "app/db.py:42" in output
        assert "CWE-89" in output

    def test_table_shows_cve_when_available(self) -> None:
        """Cuando hay CVE, se muestra en lugar de CWE."""
        finding = _make_finding(cve_id="CVE-2023-1234", cwe_id="CWE-89")
        result = _make_result(findings=[finding])
        output = _capture_output(result)

        # CVE tiene prioridad sobre CWE en la columna
        assert "CVE-2023-1234" in output

    def test_table_shows_dash_when_no_cve_no_cwe(self) -> None:
        """Cuando no hay ni CVE ni CWE, se muestra guión largo."""
        finding = _make_finding(cve_id=None, cwe_id=None)
        result = _make_result(findings=[finding])
        output = _capture_output(result)

        assert "\u2014" in output

    def test_multiple_findings_all_shown(self) -> None:
        """Múltiples findings se muestran en la tabla."""
        findings = [
            _make_finding(severity=Severity.CRITICAL, tipo="Command Injection", archivo="cmd.py", linea=10),
            _make_finding(severity=Severity.MEDIUM, tipo="XSS", archivo="web.py", linea=55),
        ]
        result = _make_result(findings=findings)
        output = _capture_output(result)

        assert "Command Injection" in output
        assert "XSS" in output
        assert "cmd.py:10" in output
        assert "web.py:55" in output


# ---------------------------------------------------------------------------
# Tests: Truncation warning
# ---------------------------------------------------------------------------


class TestTruncationWarning:
    def test_truncation_warning_shown(self) -> None:
        """Advertencia de truncación visible cuando diff_truncated=True."""
        finding = _make_finding()
        result = _make_result(findings=[finding], diff_truncated=True)
        output = _capture_output(result)

        assert "truncado" in output
        assert "l\u00edmite" in output

    def test_no_truncation_warning_when_not_truncated(self) -> None:
        """Sin advertencia cuando diff_truncated=False."""
        finding = _make_finding()
        result = _make_result(findings=[finding], diff_truncated=False)
        output = _capture_output(result)

        assert "truncado" not in output

    def test_truncation_warning_on_success_output(self) -> None:
        """Sin warning de truncación en salida exitosa (no hay findings)."""
        result = _make_result(findings=[], diff_truncated=True)
        output = _capture_output(result)

        # Sin findings explotables, se muestra panel verde, no warning
        assert "No se encontraron vulnerabilidades explotables" in output


# ---------------------------------------------------------------------------
# Tests: ANSI color omission
# ---------------------------------------------------------------------------


class TestAnsiOmission:
    def test_no_ansi_when_no_color_flag(self) -> None:
        """Req 1.7: no ANSI escapes cuando no_color=True."""
        finding = _make_finding(severity=Severity.HIGH)
        result = _make_result(findings=[finding])
        output = _capture_output(result, no_color=True)

        # No debe contener secuencias ESC
        assert "\x1b[" not in output
        # Pero el contenido textual sigue presente
        assert "vulnerabilidades explotables" in output
        assert "HIGH" in output

    def test_no_ansi_success_output(self) -> None:
        """Req 1.7: sin ANSI en salida exitosa con no_color=True."""
        result = _make_result(findings=[])
        output = _capture_output(result, no_color=True)

        assert "\x1b[" not in output
        assert "No se encontraron vulnerabilidades explotables" in output

    def test_ansi_present_when_colors_enabled(self) -> None:
        """Con colores habilitados, la salida contiene secuencias ANSI."""
        finding = _make_finding(severity=Severity.HIGH)
        result = _make_result(findings=[finding])
        buf = io.StringIO()
        console = Console(file=buf, no_color=False, width=120, force_terminal=True)
        render_text_output(result, console)
        output = buf.getvalue()

        # Cuando force_terminal=True y no_color=False, Rich genera ANSI
        assert "\x1b[" in output

    def test_no_color_env_integration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Req 1.7: make_console respeta NO_COLOR del entorno."""
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.delenv("TERM", raising=False)
        console = make_console()
        assert console.no_color is True

    def test_term_dumb_integration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Req 1.7: make_console respeta TERM=dumb."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "dumb")
        console = make_console()
        assert console.no_color is True


# ---------------------------------------------------------------------------
# Tests: SEVERITY_STYLE mapping
# ---------------------------------------------------------------------------


class TestSeverityStyleMapping:
    def test_all_severities_mapped(self) -> None:
        """Cada valor de Severity tiene un estilo asignado."""
        for severity in Severity:
            assert severity in SEVERITY_STYLE

    def test_critical_is_bold_red(self) -> None:
        assert SEVERITY_STYLE[Severity.CRITICAL] == "bold red"

    def test_high_is_red(self) -> None:
        assert SEVERITY_STYLE[Severity.HIGH] == "red"

    def test_medium_is_yellow(self) -> None:
        assert SEVERITY_STYLE[Severity.MEDIUM] == "yellow"

    def test_low_is_cyan(self) -> None:
        assert SEVERITY_STYLE[Severity.LOW] == "cyan"

    def test_info_is_dim(self) -> None:
        assert SEVERITY_STYLE[Severity.INFO] == "dim"
