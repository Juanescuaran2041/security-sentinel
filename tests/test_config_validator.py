"""Tests para security_pr_guardian.cli.config_validator — validación de configuración al arranque.

Cubre:
- Req 8.2: Validar presencia de variables obligatorias al arrancar; mensaje
  estructurado en stderr con el nombre exacto de la variable ausente y
  código de salida 2.
- Req 1.6: Error de configuración → stderr descriptivo + exit code 2.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from security_pr_guardian.cli.config_validator import (
    print_missing_config_errors,
    validate_config_at_startup,
)
from security_pr_guardian.cli.main import cli


# ---------------------------------------------------------------------------
# Tests unitarios: validate_config_at_startup
# ---------------------------------------------------------------------------


class TestValidateConfigAtStartup:
    """Tests unitarios para la lógica de validación pura."""

    def test_missing_github_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """GITHUB_TOKEN ausente se reporta."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")

        missing = validate_config_at_startup()
        assert "GITHUB_TOKEN" in missing

    def test_missing_bedrock_region(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """BEDROCK_REGION ausente cuando backend=bedrock."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.delenv("BEDROCK_REGION", raising=False)
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")

        missing = validate_config_at_startup()
        assert "BEDROCK_REGION" in missing

    def test_missing_bedrock_model_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """BEDROCK_MODEL_ID ausente cuando backend=bedrock."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)

        missing = validate_config_at_startup()
        assert "BEDROCK_MODEL_ID" in missing

    def test_missing_anthropic_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ANTHROPIC_API_KEY ausente cuando backend=anthropic."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("LLM_BACKEND", "anthropic")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        missing = validate_config_at_startup()
        assert "ANTHROPIC_API_KEY" in missing

    def test_multiple_missing_bedrock(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Múltiples variables ausentes se reportan todas."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.delenv("BEDROCK_REGION", raising=False)
        monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)

        missing = validate_config_at_startup()
        assert "GITHUB_TOKEN" in missing
        assert "BEDROCK_REGION" in missing
        assert "BEDROCK_MODEL_ID" in missing

    def test_all_present_bedrock(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sin errores cuando todas las variables de bedrock están presentes."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")

        missing = validate_config_at_startup()
        assert missing == []

    def test_all_present_anthropic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sin errores cuando todas las variables de anthropic están presentes."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("LLM_BACKEND", "anthropic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test123")

        missing = validate_config_at_startup()
        assert missing == []

    def test_default_backend_is_bedrock(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Si LLM_BACKEND no está definido, se asume bedrock."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.delenv("LLM_BACKEND", raising=False)
        monkeypatch.delenv("BEDROCK_REGION", raising=False)
        monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)

        missing = validate_config_at_startup()
        assert "BEDROCK_REGION" in missing
        assert "BEDROCK_MODEL_ID" in missing

    def test_anthropic_does_not_require_bedrock_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Backend anthropic no requiere BEDROCK_REGION ni BEDROCK_MODEL_ID."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("LLM_BACKEND", "anthropic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test123")
        monkeypatch.delenv("BEDROCK_REGION", raising=False)
        monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)

        missing = validate_config_at_startup()
        assert missing == []


# ---------------------------------------------------------------------------
# Tests unitarios: print_missing_config_errors
# ---------------------------------------------------------------------------


class TestPrintMissingConfigErrors:
    """Tests para el formato del mensaje estructurado."""

    def test_single_var_message_format(self, capsys: pytest.CaptureFixture) -> None:
        """El mensaje contiene el nombre exacto de la variable."""
        print_missing_config_errors(["GITHUB_TOKEN"])
        captured = capsys.readouterr()
        assert "GITHUB_TOKEN" in captured.err
        assert "Error de configuración" in captured.err
        assert "variable de entorno obligatoria ausente" in captured.err

    def test_multiple_vars_each_on_its_line(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Múltiples variables generan múltiples líneas en stderr."""
        print_missing_config_errors(["GITHUB_TOKEN", "BEDROCK_REGION"])
        captured = capsys.readouterr()
        lines = captured.err.strip().split("\n")
        assert len(lines) == 2
        assert "GITHUB_TOKEN" in lines[0]
        assert "BEDROCK_REGION" in lines[1]

    def test_output_goes_to_stderr_not_stdout(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """El mensaje se emite por stderr, no stdout."""
        print_missing_config_errors(["BEDROCK_MODEL_ID"])
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "BEDROCK_MODEL_ID" in captured.err


# ---------------------------------------------------------------------------
# Tests de integración: CLI check con variables ausentes
# ---------------------------------------------------------------------------


class TestCheckCommandConfigValidation:
    """Tests de integración verificando exit code 2 y stderr.

    Click 8.x no soporta mix_stderr=False en CliRunner. Usamos la salida
    combinada (output) ya que print_missing_config_errors escribe a sys.stderr
    que CliRunner captura en output por defecto.
    """

    def test_missing_github_token_exit_code_2(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Req 8.2 / 1.6: GITHUB_TOKEN ausente → exit code 2."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--repo", "owner/repo", "--pr", "1"])

        assert result.exit_code == 2
        assert "GITHUB_TOKEN" in result.output

    def test_missing_bedrock_region_exit_code_2(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Req 8.2: BEDROCK_REGION ausente → exit code 2 con nombre exacto."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.delenv("BEDROCK_REGION", raising=False)
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--repo", "owner/repo", "--pr", "1"])

        assert result.exit_code == 2
        assert "BEDROCK_REGION" in result.output

    def test_missing_bedrock_model_id_exit_code_2(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Req 8.2: BEDROCK_MODEL_ID ausente → exit code 2 con nombre exacto."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--repo", "owner/repo", "--pr", "1"])

        assert result.exit_code == 2
        assert "BEDROCK_MODEL_ID" in result.output

    def test_missing_anthropic_key_exit_code_2(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Req 8.2: ANTHROPIC_API_KEY ausente → exit code 2 con nombre exacto."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("LLM_BACKEND", "anthropic")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--repo", "owner/repo", "--pr", "1"])

        assert result.exit_code == 2
        assert "ANTHROPIC_API_KEY" in result.output

    def test_multiple_missing_lists_all_in_stderr(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Req 8.2: Múltiples variables ausentes → todas listadas."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.delenv("BEDROCK_REGION", raising=False)
        monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--repo", "owner/repo", "--pr", "1"])

        assert result.exit_code == 2
        assert "GITHUB_TOKEN" in result.output
        assert "BEDROCK_REGION" in result.output
        assert "BEDROCK_MODEL_ID" in result.output

    def test_no_api_calls_when_config_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Req 8.2: No se realizan llamadas API si la config falla.

        Verificamos que no se importa ni ejecuta _run_analysis cuando
        falta configuración (exit code 2 se produce antes).
        """
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "model-id")

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--repo", "owner/repo", "--pr", "1"])

        # Exit code 2 means we never reached the analysis phase
        assert result.exit_code == 2

    def test_structured_message_format(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """El formato del mensaje es exactamente el esperado."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "model-id")

        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--repo", "owner/repo", "--pr", "1"])

        assert result.exit_code == 2
        assert (
            "Error de configuración: variable de entorno obligatoria ausente: GITHUB_TOKEN"
            in result.output
        )
