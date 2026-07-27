"""Tests para el comando `security-guardian init` (Req 1.10).

Cubre:
- Generación de `.env.example` con todas las variables requeridas y descripciones
- Validación de credenciales: ✓ para configuradas, ✗ para ausentes
- Comportamiento con LLM_BACKEND=anthropic (ANTHROPIC_API_KEY aparece)
- Todas las variables ausentes → todas muestran ✗
- Todas las variables configuradas → todas muestran ✓
- Verificación real de GitHub token (mockeada)
- Verificación real de AWS credentials (mockeada)
- Verificación de formato de ANTHROPIC_API_KEY
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from security_pr_guardian.cli.main import cli, _generate_env_example, _verify_github_token, _verify_aws_credentials


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runner() -> CliRunner:
    """CliRunner aislado con directorio temporal."""
    return CliRunner()


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Elimina todas las variables relevantes del entorno."""
    for var in [
        "GITHUB_TOKEN",
        "BEDROCK_REGION",
        "BEDROCK_MODEL_ID",
        "LLM_BACKEND",
        "ANTHROPIC_API_KEY",
        "OSV_TIMEOUT_SECONDS",
        "MAX_DIFF_LINES",
        "MAX_DEPENDENCIES",
    ]:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def all_vars_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configura todas las variables de entorno requeridas."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test1234567890abcdefghijklmnopqrs")
    monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
    monkeypatch.setenv("LLM_BACKEND", "bedrock")


# ---------------------------------------------------------------------------
# Tests: Generación de .env.example
# ---------------------------------------------------------------------------


class TestEnvExampleGeneration:
    def test_env_example_file_created(self, runner: CliRunner, clean_env: None) -> None:
        """El comando init crea el archivo .env.example."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                result = runner.invoke(cli, ["init"])

            assert result.exit_code == 0
            assert Path(".env.example").exists()

    def test_env_example_contains_github_token(self, runner: CliRunner, clean_env: None) -> None:
        """El .env.example contiene GITHUB_TOKEN."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                runner.invoke(cli, ["init"])

            content = Path(".env.example").read_text(encoding="utf-8")
            assert "GITHUB_TOKEN" in content

    def test_env_example_contains_bedrock_region(self, runner: CliRunner, clean_env: None) -> None:
        """El .env.example contiene BEDROCK_REGION."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                runner.invoke(cli, ["init"])

            content = Path(".env.example").read_text(encoding="utf-8")
            assert "BEDROCK_REGION" in content

    def test_env_example_contains_bedrock_model_id(self, runner: CliRunner, clean_env: None) -> None:
        """El .env.example contiene BEDROCK_MODEL_ID."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                runner.invoke(cli, ["init"])

            content = Path(".env.example").read_text(encoding="utf-8")
            assert "BEDROCK_MODEL_ID" in content

    def test_env_example_contains_llm_backend(self, runner: CliRunner, clean_env: None) -> None:
        """El .env.example contiene LLM_BACKEND."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                runner.invoke(cli, ["init"])

            content = Path(".env.example").read_text(encoding="utf-8")
            assert "LLM_BACKEND" in content

    def test_env_example_contains_anthropic_api_key(self, runner: CliRunner, clean_env: None) -> None:
        """El .env.example contiene ANTHROPIC_API_KEY."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                runner.invoke(cli, ["init"])

            content = Path(".env.example").read_text(encoding="utf-8")
            assert "ANTHROPIC_API_KEY" in content

    def test_env_example_contains_osv_timeout(self, runner: CliRunner, clean_env: None) -> None:
        """El .env.example contiene OSV_TIMEOUT_SECONDS."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                runner.invoke(cli, ["init"])

            content = Path(".env.example").read_text(encoding="utf-8")
            assert "OSV_TIMEOUT_SECONDS" in content

    def test_env_example_contains_max_diff_lines(self, runner: CliRunner, clean_env: None) -> None:
        """El .env.example contiene MAX_DIFF_LINES."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                runner.invoke(cli, ["init"])

            content = Path(".env.example").read_text(encoding="utf-8")
            assert "MAX_DIFF_LINES" in content

    def test_env_example_contains_max_dependencies(self, runner: CliRunner, clean_env: None) -> None:
        """El .env.example contiene MAX_DEPENDENCIES."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                runner.invoke(cli, ["init"])

            content = Path(".env.example").read_text(encoding="utf-8")
            assert "MAX_DEPENDENCIES" in content

    def test_env_example_contains_all_required_variables(self, runner: CliRunner, clean_env: None) -> None:
        """El .env.example contiene TODAS las variables requeridas."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                runner.invoke(cli, ["init"])

            content = Path(".env.example").read_text(encoding="utf-8")
            required_vars = [
                "GITHUB_TOKEN",
                "BEDROCK_REGION",
                "BEDROCK_MODEL_ID",
                "LLM_BACKEND",
                "ANTHROPIC_API_KEY",
                "OSV_TIMEOUT_SECONDS",
                "MAX_DIFF_LINES",
                "MAX_DEPENDENCIES",
            ]
            for var in required_vars:
                assert var in content, f"Variable {var} no encontrada en .env.example"

    def test_env_example_contains_descriptions(self, runner: CliRunner, clean_env: None) -> None:
        """El .env.example incluye descripciones/comentarios para las variables."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                runner.invoke(cli, ["init"])

            content = Path(".env.example").read_text(encoding="utf-8")
            # Debe haber comentarios con descripciones
            assert "# [REQUERIDO]" in content
            assert "# [OPCIONAL]" in content

    def test_init_shows_success_message(self, runner: CliRunner, clean_env: None) -> None:
        """El comando init muestra mensaje de éxito tras generar .env.example."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                result = runner.invoke(cli, ["init"])

            assert ".env.example" in result.output
            assert "generado" in result.output


# ---------------------------------------------------------------------------
# Tests: Validación de credenciales — todas ausentes
# ---------------------------------------------------------------------------


class TestCredentialValidationAllMissing:
    def test_all_missing_shows_x_marks(self, runner: CliRunner, clean_env: None) -> None:
        """Con todas las variables ausentes, se muestran ✗ para cada una."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                result = runner.invoke(cli, ["init"])

            output = result.output
            assert "no configurado" in output
            assert "GITHUB_TOKEN" in output
            assert "BEDROCK_REGION" in output
            assert "BEDROCK_MODEL_ID" in output

    def test_all_missing_shows_warning_message(self, runner: CliRunner, clean_env: None) -> None:
        """Con variables ausentes, se muestra mensaje de advertencia."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=False
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=False
            ):
                result = runner.invoke(cli, ["init"])

            assert "Algunas credenciales no están configuradas" in result.output


# ---------------------------------------------------------------------------
# Tests: Validación de credenciales — todas configuradas
# ---------------------------------------------------------------------------


class TestCredentialValidationAllSet:
    def test_all_set_shows_check_marks(
        self, runner: CliRunner, all_vars_set: None
    ) -> None:
        """Con todas las variables configuradas, se muestran ✓ para cada una."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=True
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=True
            ):
                result = runner.invoke(cli, ["init"])

            output = result.output
            assert "GITHUB_TOKEN" in output
            assert "BEDROCK_REGION" in output
            assert "BEDROCK_MODEL_ID" in output
            # Should show "configurado" for each
            assert "configurado" in output

    def test_all_set_shows_success_message(
        self, runner: CliRunner, all_vars_set: None
    ) -> None:
        """Con todas configuradas, se muestra mensaje de éxito."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=True
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=True
            ):
                result = runner.invoke(cli, ["init"])

            assert "Todas las credenciales están configuradas correctamente" in result.output

    def test_github_token_valid_shows_valid(
        self, runner: CliRunner, all_vars_set: None
    ) -> None:
        """Un token de GitHub válido muestra 'válido'."""
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=True
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=True
            ):
                result = runner.invoke(cli, ["init"])

            assert "válido" in result.output


# ---------------------------------------------------------------------------
# Tests: Validación con LLM_BACKEND=anthropic
# ---------------------------------------------------------------------------


class TestCredentialValidationAnthropicBackend:
    def test_anthropic_key_check_appears(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Con LLM_BACKEND=anthropic, ANTHROPIC_API_KEY se valida."""
        monkeypatch.setenv("LLM_BACKEND", "anthropic")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api123key456")

        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=True
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=True
            ):
                result = runner.invoke(cli, ["init"])

            assert "ANTHROPIC_API_KEY" in result.output

    def test_anthropic_key_missing_shows_x(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Con LLM_BACKEND=anthropic y ANTHROPIC_API_KEY ausente, se muestra ✗."""
        monkeypatch.setenv("LLM_BACKEND", "anthropic")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=True
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=True
            ):
                result = runner.invoke(cli, ["init"])

            assert "ANTHROPIC_API_KEY" in result.output
            assert "no configurado" in result.output

    def test_anthropic_key_valid_format(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Con ANTHROPIC_API_KEY con prefijo sk-ant-, se muestra formato válido."""
        monkeypatch.setenv("LLM_BACKEND", "anthropic")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-validkey123456789")

        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=True
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=True
            ):
                result = runner.invoke(cli, ["init"])

            assert "formato válido" in result.output

    def test_anthropic_key_invalid_format(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Con ANTHROPIC_API_KEY sin prefijo sk-ant-, se muestra formato inesperado."""
        monkeypatch.setenv("LLM_BACKEND", "anthropic")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "invalid-key-format")

        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=True
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=True
            ):
                result = runner.invoke(cli, ["init"])

            assert "formato inesperado" in result.output

    def test_anthropic_check_not_shown_for_bedrock_backend(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Con LLM_BACKEND=bedrock (default), ANTHROPIC_API_KEY no se valida."""
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("BEDROCK_REGION", "us-east-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main._verify_github_token", return_value=True
            ), patch(
                "security_pr_guardian.cli.main._verify_aws_credentials", return_value=True
            ):
                result = runner.invoke(cli, ["init"])

            # ANTHROPIC_API_KEY should not appear as a validation check
            # (it's still in .env.example as a comment, but not in credential validation output)
            # The validation output should not mention it's "no configurado"
            assert "no configurado" not in result.output


# ---------------------------------------------------------------------------
# Tests: Verificación real de GitHub token (mockeada)
# ---------------------------------------------------------------------------


class TestVerifyGitHubToken:
    def test_valid_token_returns_true(self) -> None:
        """Un token válido (respuesta 200) retorna True."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        with patch("httpx.get", return_value=mock_response):
            result = _verify_github_token("ghp_validtoken123")
            assert result is True

    def test_invalid_token_returns_false(self) -> None:
        """Un token inválido (respuesta 401) retorna False."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        with patch("httpx.get", return_value=mock_response):
            result = _verify_github_token("ghp_invalidtoken")
            assert result is False

    def test_network_error_returns_false(self) -> None:
        """Un error de red retorna False sin crashear."""
        with patch("httpx.get", side_effect=Exception("Connection refused")):
            result = _verify_github_token("ghp_sometoken")
            assert result is False

    def test_timeout_returns_false(self) -> None:
        """Un timeout retorna False sin crashear."""
        import httpx as real_httpx

        with patch("httpx.get", side_effect=real_httpx.TimeoutException("timeout")):
            result = _verify_github_token("ghp_sometoken")
            assert result is False


# ---------------------------------------------------------------------------
# Tests: Verificación de AWS credentials (mockeada)
# ---------------------------------------------------------------------------


class TestVerifyAWSCredentials:
    def test_valid_credentials_returns_true(self) -> None:
        """Credenciales AWS válidas retornan True."""
        mock_client = MagicMock()
        mock_client.get_caller_identity.return_value = {
            "UserId": "AIDASAMPLE",
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/testuser",
        }
        with patch("boto3.client", return_value=mock_client):
            result = _verify_aws_credentials("us-east-1")
            assert result is True

    def test_invalid_credentials_returns_false(self) -> None:
        """Credenciales AWS inválidas retornan False."""
        mock_client = MagicMock()
        mock_client.get_caller_identity.side_effect = Exception(
            "InvalidClientTokenId"
        )
        with patch("boto3.client", return_value=mock_client):
            result = _verify_aws_credentials("us-east-1")
            assert result is False

    def test_no_credentials_configured_returns_false(self) -> None:
        """Sin credenciales configuradas retorna False."""
        with patch("boto3.client", side_effect=Exception("NoCredentialsError")):
            result = _verify_aws_credentials("us-east-1")
            assert result is False


# ---------------------------------------------------------------------------
# Tests: _generate_env_example content
# ---------------------------------------------------------------------------


class TestGenerateEnvExample:
    def test_returns_non_empty_string(self) -> None:
        """_generate_env_example retorna un string no vacío."""
        content = _generate_env_example()
        assert isinstance(content, str)
        assert len(content) > 0

    def test_has_header_comment(self) -> None:
        """El contenido tiene un header descriptivo."""
        content = _generate_env_example()
        assert "Security PR Guardian" in content

    def test_contains_example_values(self) -> None:
        """El contenido incluye valores de ejemplo para las variables."""
        content = _generate_env_example()
        assert "ghp_" in content  # Example GitHub token format
        assert "us-east-1" in content  # Example region
        assert "anthropic.claude" in content  # Example model ID
