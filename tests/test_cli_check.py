"""Tests unitarios del CLI `security-guardian check` (Task 10.6).

Cubre:
- Código de salida 0: análisis completo sin hallazgos explotables
- Código de salida 1: análisis completo con al menos un hallazgo explotable
- Código de salida 2: argumentos inválidos (--repo o --pr faltante)
- Código de salida 2: variable de entorno obligatoria ausente
- `--output json` produce JSON parseable con claves requeridas
- `--no-comment` pasa dry_run=True a _run_analysis
- ANSI omitido cuando NO_COLOR está presente
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from security_pr_guardian.cli.main import cli
from security_pr_guardian.core.models import (
    AnalysisResult,
    ConfirmedFinding,
    Recommendation,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers — AnalysisResult factories
# ---------------------------------------------------------------------------


def _make_clean_result() -> AnalysisResult:
    """AnalysisResult sin hallazgos explotables (exit code 0)."""
    return AnalysisResult(
        analysis_id="test-clean-id",
        repo="owner/repo",
        pr_number=1,
        candidate_count=5,
        confirmed_count=0,
        discarded_count=3,
        not_evaluated_count=2,
        confirmed_findings=[],
        diff_truncated=False,
        dependency_limit_exceeded=False,
        duration_seconds=1.5,
        model_id="test-model",
        guardian_version="0.1.0",
        timestamp_utc=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


def _make_exploitable_result() -> AnalysisResult:
    """AnalysisResult con al menos un hallazgo explotable (exit code 1)."""
    finding = ConfirmedFinding(
        finding_id="f-001",
        source="static",
        tipo_vulnerabilidad="SQL Injection",
        archivo="app/db.py",
        linea_inicio=42,
        linea_fin=42,
        fragmento_codigo="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        cwe_id="CWE-89",
        cve_id=None,
        severidad_ajustada=Severity.HIGH,
        justificacion=(
            "La consulta SQL se construye mediante f-string con entrada del usuario "
            "sin sanitizar, permitiendo inyeccion SQL directa. Un atacante puede "
            "modificar la consulta para extraer datos arbitrarios."
        ),
        recomendacion=Recommendation(
            descripcion="Usar consultas parametrizadas",
            codigo_corregido="cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
            referencia="CWE-89",
        ),
        disposition="incluido",
    )
    return AnalysisResult(
        analysis_id="test-exploitable-id",
        repo="owner/repo",
        pr_number=1,
        candidate_count=5,
        confirmed_count=1,
        discarded_count=3,
        not_evaluated_count=1,
        confirmed_findings=[finding],
        diff_truncated=False,
        dependency_limit_exceeded=False,
        duration_seconds=2.0,
        model_id="test-model",
        guardian_version="0.1.0",
        timestamp_utc=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runner() -> CliRunner:
    """CliRunner aislado."""
    return CliRunner()


@pytest.fixture
def env_vars_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configura todas las variables de entorno requeridas para que check pase la validación."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test1234567890abcdefghijklmnopqrs")
    monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
    monkeypatch.setenv("LLM_BACKEND", "bedrock")


# ---------------------------------------------------------------------------
# Tests: Código de salida 0 — sin hallazgos explotables
# ---------------------------------------------------------------------------


class TestExitCode0NoExploitable:
    """Exit code 0 cuando el análisis completa sin hallazgos explotables."""

    def test_exit_code_0_clean_analysis(
        self, runner: CliRunner, env_vars_set: None
    ) -> None:
        """Análisis sin findings explotables retorna exit code 0."""
        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
            return_value=_make_clean_result(),
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1"]
            )

        assert result.exit_code == 0

    def test_exit_code_0_with_discarded_findings(
        self, runner: CliRunner, env_vars_set: None
    ) -> None:
        """Findings descartados (disposition='descartado') no causan exit code 1."""
        discarded_finding = ConfirmedFinding(
            finding_id="f-002",
            source="static",
            tipo_vulnerabilidad="Hardcoded Secret",
            archivo="config/test.py",
            linea_inicio=10,
            linea_fin=10,
            fragmento_codigo="PASSWORD = 'test_only'",
            cwe_id="CWE-798",
            cve_id=None,
            severidad_ajustada=Severity.LOW,
            justificacion=(
                "Este valor es un placeholder de testing que no se usa en produccion. "
                "No representa un riesgo real ya que el archivo es solo para tests unitarios."
            ),
            recomendacion=Recommendation(
                descripcion="Considerar uso de variables de entorno",
                codigo_corregido="PASSWORD = os.environ['TEST_PASSWORD']",
                referencia="CWE-798",
            ),
            disposition="descartado",
        )
        result_data = _make_clean_result()
        result_data = result_data.model_copy(
            update={
                "confirmed_findings": [discarded_finding],
                "discarded_count": 1,
            }
        )

        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
            return_value=result_data,
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1"]
            )

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Tests: Código de salida 1 — al menos un hallazgo explotable
# ---------------------------------------------------------------------------


class TestExitCode1Exploitable:
    """Exit code 1 cuando hay al menos un hallazgo con disposition='incluido'."""

    def test_exit_code_1_with_exploitable_finding(
        self, runner: CliRunner, env_vars_set: None
    ) -> None:
        """Un finding con disposition='incluido' produce exit code 1."""
        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
            return_value=_make_exploitable_result(),
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1"]
            )

        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Tests: Código de salida 2 — argumentos inválidos
# ---------------------------------------------------------------------------


class TestExitCode2InvalidArgs:
    """Exit code 2 cuando faltan argumentos requeridos del CLI."""

    def test_missing_repo_arg(self, runner: CliRunner, env_vars_set: None) -> None:
        """--repo faltante produce exit code 2."""
        result = runner.invoke(cli, ["check", "--pr", "1"])
        assert result.exit_code == 2

    def test_missing_pr_arg(self, runner: CliRunner, env_vars_set: None) -> None:
        """--pr faltante produce exit code 2."""
        result = runner.invoke(cli, ["check", "--repo", "owner/repo"])
        assert result.exit_code == 2

    def test_missing_both_args(self, runner: CliRunner, env_vars_set: None) -> None:
        """Ambos --repo y --pr faltantes producen exit code 2."""
        result = runner.invoke(cli, ["check"])
        assert result.exit_code == 2

    def test_invalid_repo_format(
        self, runner: CliRunner, env_vars_set: None
    ) -> None:
        """Formato de repo inválido (sin '/') produce exit code 2."""
        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "invalid-repo", "--pr", "1"]
            )

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Tests: Código de salida 2 — variable obligatoria ausente
# ---------------------------------------------------------------------------


class TestExitCode2MissingEnvVar:
    """Exit code 2 cuando una variable de entorno obligatoria está ausente."""

    def test_missing_github_token(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """GITHUB_TOKEN ausente produce exit code 2."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")
        monkeypatch.setenv("LLM_BACKEND", "bedrock")

        result = runner.invoke(cli, ["check", "--repo", "owner/repo", "--pr", "1"])
        assert result.exit_code == 2

    def test_missing_bedrock_region(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """BEDROCK_REGION ausente produce exit code 2."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.delenv("BEDROCK_REGION", raising=False)
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")

        result = runner.invoke(cli, ["check", "--repo", "owner/repo", "--pr", "1"])
        assert result.exit_code == 2

    def test_error_message_contains_variable_name(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """El mensaje de error contiene el nombre exacto de la variable ausente."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")
        monkeypatch.setenv("LLM_BACKEND", "bedrock")

        result = runner.invoke(cli, ["check", "--repo", "owner/repo", "--pr", "1"])
        assert result.exit_code == 2
        assert "GITHUB_TOKEN" in result.output


# ---------------------------------------------------------------------------
# Tests: --output json produce JSON parseable
# ---------------------------------------------------------------------------


class TestOutputJson:
    """--output json produce salida JSON parseable con las claves requeridas."""

    def test_json_output_is_parseable(
        self, runner: CliRunner, env_vars_set: None
    ) -> None:
        """La salida con --output json es JSON válido."""
        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
            return_value=_make_clean_result(),
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1", "--output", "json"]
            )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, dict)

    def test_json_output_contains_required_keys(
        self, runner: CliRunner, env_vars_set: None
    ) -> None:
        """La salida JSON contiene las claves requeridas del AnalysisResult."""
        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
            return_value=_make_clean_result(),
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1", "--output", "json"]
            )

        data = json.loads(result.output)
        required_keys = [
            "analysis_id",
            "repo",
            "pr_number",
            "confirmed_count",
            "discarded_count",
            "confirmed_findings",
            "diff_truncated",
        ]
        for key in required_keys:
            assert key in data, f"Clave '{key}' faltante en salida JSON"

    def test_json_output_with_findings(
        self, runner: CliRunner, env_vars_set: None
    ) -> None:
        """La salida JSON con findings explotables es parseable y exit code 1."""
        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
            return_value=_make_exploitable_result(),
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1", "--output", "json"]
            )

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["confirmed_count"] == 1
        assert len(data["confirmed_findings"]) == 1

    def test_json_output_no_ansi_sequences(
        self, runner: CliRunner, env_vars_set: None
    ) -> None:
        """La salida JSON no contiene secuencias ANSI."""
        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
            return_value=_make_exploitable_result(),
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1", "--output", "json"]
            )

        assert "\x1b[" not in result.output


# ---------------------------------------------------------------------------
# Tests: --no-comment omite PRCommentPort
# ---------------------------------------------------------------------------


class TestNoComment:
    """--no-comment pasa no_comment=True a _run_analysis (dry-run)."""

    def test_no_comment_passes_true_to_run_analysis(
        self, runner: CliRunner, env_vars_set: None
    ) -> None:
        """El flag --no-comment se propaga como no_comment=True a _run_analysis."""
        mock_run = AsyncMock(return_value=_make_clean_result())

        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            mock_run,
        ):
            result = runner.invoke(
                cli,
                ["check", "--repo", "owner/repo", "--pr", "1", "--no-comment"],
            )

        assert result.exit_code == 0
        # _run_analysis recibe (config, repo, pr_number, no_comment, logger)
        call_args = mock_run.call_args
        # no_comment es el 4to argumento posicional (index 3)
        assert call_args[0][3] is True

    def test_without_no_comment_passes_false(
        self, runner: CliRunner, env_vars_set: None
    ) -> None:
        """Sin --no-comment, se propaga no_comment=False a _run_analysis."""
        mock_run = AsyncMock(return_value=_make_clean_result())

        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            mock_run,
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1"]
            )

        assert result.exit_code == 0
        call_args = mock_run.call_args
        assert call_args[0][3] is False


# ---------------------------------------------------------------------------
# Tests: ANSI omitido con NO_COLOR
# ---------------------------------------------------------------------------


class TestNoColorAnsiOmitted:
    """NO_COLOR en el entorno omite secuencias ANSI en la salida."""

    def test_no_ansi_with_no_color_env_var(
        self, runner: CliRunner, env_vars_set: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Con NO_COLOR=1, la salida no contiene secuencias de escape ANSI."""
        monkeypatch.setenv("NO_COLOR", "1")

        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
            return_value=_make_exploitable_result(),
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1"]
            )

        assert "\x1b[" not in result.output

    def test_no_ansi_with_no_color_empty_value(
        self, runner: CliRunner, env_vars_set: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Con NO_COLOR='' (valor vacío), la salida no contiene ANSI (spec NO_COLOR)."""
        monkeypatch.setenv("NO_COLOR", "")

        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
            return_value=_make_exploitable_result(),
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1"]
            )

        assert "\x1b[" not in result.output

    def test_no_ansi_with_term_dumb(
        self, runner: CliRunner, env_vars_set: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Con TERM=dumb, la salida no contiene secuencias ANSI."""
        monkeypatch.setenv("TERM", "dumb")
        monkeypatch.delenv("NO_COLOR", raising=False)

        with patch(
            "security_pr_guardian.cli.main._run_analysis",
            new_callable=AsyncMock,
            return_value=_make_exploitable_result(),
        ):
            result = runner.invoke(
                cli, ["check", "--repo", "owner/repo", "--pr", "1"]
            )

        assert "\x1b[" not in result.output
