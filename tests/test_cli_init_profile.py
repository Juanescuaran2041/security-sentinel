"""Tests para `security-guardian init --profile` y `--auto-detect` (tareas 14.4 y 14.5).

Cubre:
- Generación correcta de .security-guardian.yml con las respuestas del usuario
- YAML generado con la estructura `team_profile: {...}` correcta
- Cuestionario con valores por defecto cuando ya existe .security-guardian.yml
- Confirmación antes de sobrescribir un archivo existente (acepta y rechaza)
- Flag --auto-detect pre-rellena frameworks/auth_libs detectados
- --auto-detect no crashea aunque no existan manifiestos
- _build_profile_yaml_dict genera la estructura YAML esperada
- Funciones de conveniencia del módulo auto_detect (detect_frameworks, etc.)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import yaml
from click.testing import CliRunner

from security_pr_guardian.cli.main import cli, _build_profile_yaml_dict, _SEVERITY_CHOICES
from security_pr_guardian.core.models import AllowedPattern, TeamProfile, Severity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# Helper: simula respuestas del usuario en el cuestionario
# ---------------------------------------------------------------------------


def _make_inputs(*answers: str) -> str:
    """Construye la cadena de input para el CliRunner concatenando respuestas."""
    return "\n".join(answers) + "\n"


# ---------------------------------------------------------------------------
# Tests: generación básica de .security-guardian.yml
# ---------------------------------------------------------------------------


class TestProfileGeneration:
    def test_profile_file_created(self, runner: CliRunner) -> None:
        """init --profile crea .security-guardian.yml."""
        inputs = _make_inputs(
            "django, fastapi",   # frameworks
            "bcrypt",            # auth libs
            "n",                 # no añadir allowed patterns
            "low",               # min severity
            "",                  # no custom exceptions
        )
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["init", "--profile"], input=inputs)
            assert Path(".security-guardian.yml").exists(), result.output

    def test_profile_yaml_structure(self, runner: CliRunner) -> None:
        """El YAML generado contiene la clave raíz team_profile."""
        inputs = _make_inputs(
            "django",
            "bcrypt",
            "n",
            "high",
            "",
        )
        with runner.isolated_filesystem():
            runner.invoke(cli, ["init", "--profile"], input=inputs)
            data = yaml.safe_load(Path(".security-guardian.yml").read_text(encoding="utf-8"))
            assert "team_profile" in data

    def test_profile_frameworks_written(self, runner: CliRunner) -> None:
        """Los frameworks introducidos se escriben en team_profile.frameworks."""
        inputs = _make_inputs(
            "react, vue",
            "",
            "n",
            "medium",
            "",
        )
        with runner.isolated_filesystem():
            runner.invoke(cli, ["init", "--profile"], input=inputs)
            data = yaml.safe_load(Path(".security-guardian.yml").read_text(encoding="utf-8"))
            frameworks = data["team_profile"]["frameworks"]
            assert "react" in frameworks
            assert "vue" in frameworks

    def test_profile_auth_libraries_written(self, runner: CliRunner) -> None:
        """Las librerías de auth se escriben en team_profile.auth_libraries."""
        inputs = _make_inputs(
            "",
            "passlib, argon2-cffi",
            "n",
            "low",
            "",
        )
        with runner.isolated_filesystem():
            runner.invoke(cli, ["init", "--profile"], input=inputs)
            data = yaml.safe_load(Path(".security-guardian.yml").read_text(encoding="utf-8"))
            auth = data["team_profile"]["auth_libraries"]
            assert "passlib" in auth
            assert "argon2-cffi" in auth

    def test_profile_min_severity_written(self, runner: CliRunner) -> None:
        """La severidad mínima se escribe correctamente."""
        inputs = _make_inputs(
            "",
            "",
            "n",
            "critical",
            "",
        )
        with runner.isolated_filesystem():
            runner.invoke(cli, ["init", "--profile"], input=inputs)
            data = yaml.safe_load(Path(".security-guardian.yml").read_text(encoding="utf-8"))
            assert data["team_profile"]["min_severity"] == "critical"

    def test_profile_custom_exceptions_written(self, runner: CliRunner) -> None:
        """Las excepciones del equipo se escriben en team_profile.custom_exceptions."""
        inputs = _make_inputs(
            "",
            "",
            "n",
            "low",
            "pickle en cache interno; logs sensibles permitidos",
        )
        with runner.isolated_filesystem():
            runner.invoke(cli, ["init", "--profile"], input=inputs)
            data = yaml.safe_load(Path(".security-guardian.yml").read_text(encoding="utf-8"))
            exceptions = data["team_profile"]["custom_exceptions"]
            assert len(exceptions) == 2
            assert any("pickle" in e for e in exceptions)

    def test_profile_allowed_pattern_written(self, runner: CliRunner) -> None:
        """Un allowed_pattern introducido se escribe con cwe_id y razon."""
        inputs = _make_inputs(
            "",
            "",
            "y",          # sí añadir patrón
            "CWE-327",    # cwe_id
            "md5 para ETags, no criptografía",  # razon
            "n",          # no añadir más
            "low",
            "",
        )
        with runner.isolated_filesystem():
            runner.invoke(cli, ["init", "--profile"], input=inputs)
            data = yaml.safe_load(Path(".security-guardian.yml").read_text(encoding="utf-8"))
            patterns = data["team_profile"]["allowed_patterns"]
            assert len(patterns) == 1
            assert patterns[0]["cwe_id"] == "CWE-327"
            assert "ETags" in patterns[0]["razon"]

    def test_success_message_shown(self, runner: CliRunner) -> None:
        """Se muestra un mensaje de éxito con la ruta del archivo."""
        inputs = _make_inputs("", "", "n", "low", "")
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["init", "--profile"], input=inputs)
            assert ".security-guardian.yml" in result.output

    def test_invalid_severity_falls_back_to_default(self, runner: CliRunner) -> None:
        """Una severidad inválida cae al default 'low'."""
        inputs = _make_inputs(
            "",
            "",
            "n",
            "INVALID_LEVEL",
            "",
        )
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["init", "--profile"], input=inputs)
            data = yaml.safe_load(Path(".security-guardian.yml").read_text(encoding="utf-8"))
            assert data["team_profile"]["min_severity"] == "low"


# ---------------------------------------------------------------------------
# Tests: archivo existente — carga defaults y pide confirmación
# ---------------------------------------------------------------------------


class TestProfileOverwriteExisting:
    def _create_existing_profile(self, path: Path) -> None:
        """Escribe un .security-guardian.yml con valores de prueba."""
        content = {
            "team_profile": {
                "frameworks": ["flask"],
                "auth_libraries": ["pyjwt"],
                "allowed_patterns": [],
                "min_severity": "medium",
                "custom_exceptions": ["excepción existente"],
            }
        }
        path.write_text(
            yaml.dump(content, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )

    def test_shows_existing_file_warning(self, runner: CliRunner) -> None:
        """Cuando el archivo existe, se muestra un aviso al usuario."""
        inputs = _make_inputs(
            "flask",       # frameworks (acepta default)
            "pyjwt",
            "n",
            "medium",
            "",
            "n",           # NO sobrescribir
        )
        with runner.isolated_filesystem():
            self._create_existing_profile(Path(".security-guardian.yml"))
            result = runner.invoke(cli, ["init", "--profile"], input=inputs)
            assert ".security-guardian.yml" in result.output

    def test_cancels_when_user_rejects_overwrite(self, runner: CliRunner) -> None:
        """Si el usuario rechaza sobrescribir, el archivo no cambia."""
        original_content = {
            "team_profile": {
                "frameworks": ["flask"],
                "auth_libraries": ["pyjwt"],
                "allowed_patterns": [],
                "min_severity": "medium",
                "custom_exceptions": [],
            }
        }
        inputs = _make_inputs(
            "new-framework",
            "",
            "n",
            "critical",
            "",
            "n",   # rechaza sobrescribir
        )
        with runner.isolated_filesystem():
            profile_path = Path(".security-guardian.yml")
            profile_path.write_text(
                yaml.dump(original_content, default_flow_style=False),
                encoding="utf-8",
            )
            runner.invoke(cli, ["init", "--profile"], input=inputs)
            # El archivo no debe haber cambiado
            data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
            assert data["team_profile"]["frameworks"] == ["flask"]

    def test_overwrites_when_user_confirms(self, runner: CliRunner) -> None:
        """Si el usuario confirma, el archivo se sobreescribe."""
        inputs = _make_inputs(
            "django",   # nuevo framework
            "bcrypt",
            "n",
            "high",
            "",
            "y",        # sí sobrescribir
        )
        with runner.isolated_filesystem():
            profile_path = Path(".security-guardian.yml")
            # Crear archivo con valor inicial distinto
            old = {"team_profile": {"frameworks": ["old-fw"], "auth_libraries": [],
                                    "allowed_patterns": [], "min_severity": "low",
                                    "custom_exceptions": []}}
            profile_path.write_text(yaml.dump(old), encoding="utf-8")
            runner.invoke(cli, ["init", "--profile"], input=inputs)
            data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
            assert "django" in data["team_profile"]["frameworks"]


# ---------------------------------------------------------------------------
# Tests: --auto-detect pre-rellena valores
# ---------------------------------------------------------------------------


class TestAutoDetect:
    def test_auto_detect_uses_detected_frameworks(self, runner: CliRunner) -> None:
        """Con --auto-detect, los frameworks detectados se usan como default."""
        # Simular que auto_detect_profile devuelve un resultado
        mock_detected = {
            "frameworks": ["fastapi"],
            "auth_libraries": ["bcrypt"],
            "min_severity": "medium",
        }
        inputs = _make_inputs(
            "",    # acepta frameworks por defecto
            "",    # acepta auth_libs por defecto
            "n",
            "",    # acepta severidad por defecto
            "",
        )
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main.auto_detect_profile",
                return_value=mock_detected,
            ):
                result = runner.invoke(
                    cli, ["init", "--profile", "--auto-detect"], input=inputs
                )
            assert result.exit_code == 0
            data = yaml.safe_load(Path(".security-guardian.yml").read_text(encoding="utf-8"))
            assert "fastapi" in data["team_profile"]["frameworks"]

    def test_auto_detect_no_crash_without_manifests(self, runner: CliRunner) -> None:
        """--auto-detect no crashea en un directorio vacío."""
        inputs = _make_inputs("", "", "n", "low", "")
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli, ["init", "--profile", "--auto-detect"], input=inputs
            )
            # Debe terminar sin excepción
            assert result.exit_code == 0

    def test_auto_detect_graceful_on_exception(self, runner: CliRunner) -> None:
        """--auto-detect degrada grácilmente si la detección falla."""
        inputs = _make_inputs("django", "bcrypt", "n", "low", "")
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main.auto_detect_profile",
                side_effect=RuntimeError("fallo simulado"),
            ):
                result = runner.invoke(
                    cli, ["init", "--profile", "--auto-detect"], input=inputs
                )
            assert result.exit_code == 0
            assert Path(".security-guardian.yml").exists()

    def test_auto_detect_fills_severity_from_bandit(self, runner: CliRunner) -> None:
        """--auto-detect usa la severidad detectada por el linter como default."""
        mock_detected = {
            "frameworks": [],
            "auth_libraries": [],
            "min_severity": "high",
        }
        inputs = _make_inputs("", "", "n", "", "")  # acepta los defaults
        with runner.isolated_filesystem():
            with patch(
                "security_pr_guardian.cli.main.auto_detect_profile",
                return_value=mock_detected,
            ):
                result = runner.invoke(
                    cli, ["init", "--profile", "--auto-detect"], input=inputs
                )
            data = yaml.safe_load(Path(".security-guardian.yml").read_text(encoding="utf-8"))
            assert data["team_profile"]["min_severity"] == "high"


# ---------------------------------------------------------------------------
# Tests: init sin --profile no toca .security-guardian.yml
# ---------------------------------------------------------------------------


class TestInitWithoutProfile:
    def test_init_without_profile_creates_env_example(self, runner: CliRunner) -> None:
        """init sin --profile crea .env.example como antes."""
        with runner.isolated_filesystem():
            with (
                patch("security_pr_guardian.cli.main._verify_github_token", return_value=False),
                patch("security_pr_guardian.cli.main._verify_aws_credentials", return_value=False),
            ):
                result = runner.invoke(cli, ["init"])
            assert result.exit_code == 0
            assert Path(".env.example").exists()

    def test_init_without_profile_no_security_yml(self, runner: CliRunner) -> None:
        """init sin --profile NO crea .security-guardian.yml."""
        with runner.isolated_filesystem():
            with (
                patch("security_pr_guardian.cli.main._verify_github_token", return_value=False),
                patch("security_pr_guardian.cli.main._verify_aws_credentials", return_value=False),
            ):
                runner.invoke(cli, ["init"])
            assert not Path(".security-guardian.yml").exists()


# ---------------------------------------------------------------------------
# Tests: _build_profile_yaml_dict
# ---------------------------------------------------------------------------


class TestBuildProfileYamlDict:
    def test_returns_dict_with_team_profile_key(self) -> None:
        result = _build_profile_yaml_dict([], [], [], "low", [])
        assert "team_profile" in result

    def test_frameworks_written(self) -> None:
        result = _build_profile_yaml_dict(["django", "react"], [], [], "low", [])
        assert result["team_profile"]["frameworks"] == ["django", "react"]

    def test_auth_libraries_written(self) -> None:
        result = _build_profile_yaml_dict([], ["bcrypt", "passlib"], [], "low", [])
        assert result["team_profile"]["auth_libraries"] == ["bcrypt", "passlib"]

    def test_allowed_patterns_serialized(self) -> None:
        patterns = [AllowedPattern(cwe_id="CWE-89", razon="test reason")]
        result = _build_profile_yaml_dict([], [], patterns, "medium", [])
        p = result["team_profile"]["allowed_patterns"]
        assert len(p) == 1
        assert p[0]["cwe_id"] == "CWE-89"
        assert p[0]["razon"] == "test reason"

    def test_min_severity_written(self) -> None:
        result = _build_profile_yaml_dict([], [], [], "critical", [])
        assert result["team_profile"]["min_severity"] == "critical"

    def test_custom_exceptions_written(self) -> None:
        result = _build_profile_yaml_dict([], [], [], "low", ["excepción 1", "excepción 2"])
        assert result["team_profile"]["custom_exceptions"] == ["excepción 1", "excepción 2"]

    def test_empty_fields_are_empty_lists(self) -> None:
        result = _build_profile_yaml_dict([], [], [], "low", [])
        tp = result["team_profile"]
        assert tp["frameworks"] == []
        assert tp["auth_libraries"] == []
        assert tp["allowed_patterns"] == []
        assert tp["custom_exceptions"] == []

    def test_yaml_serializable(self) -> None:
        """El dict resultante debe ser serializable a YAML sin errores."""
        patterns = [AllowedPattern(cwe_id="CWE-79", razon="XSS permitido en admin")]
        result = _build_profile_yaml_dict(
            ["flask"], ["pyjwt"], patterns, "high", ["logs internos"]
        )
        dumped = yaml.dump(result, default_flow_style=False, allow_unicode=True)
        restored = yaml.safe_load(dumped)
        assert restored["team_profile"]["frameworks"] == ["flask"]


# ---------------------------------------------------------------------------
# Tests: funciones de conveniencia en auto_detect
# ---------------------------------------------------------------------------


class TestAutoDetectConvenienceFunctions:
    def test_detect_frameworks_returns_list(self, tmp_path: Path) -> None:
        from security_pr_guardian.core.auto_detect import detect_frameworks
        result = detect_frameworks(cwd=tmp_path)
        assert isinstance(result, list)

    def test_detect_auth_libraries_returns_list(self, tmp_path: Path) -> None:
        from security_pr_guardian.core.auto_detect import detect_auth_libraries
        result = detect_auth_libraries(cwd=tmp_path)
        assert isinstance(result, list)

    def test_detect_min_severity_returns_none_or_str(self, tmp_path: Path) -> None:
        from security_pr_guardian.core.auto_detect import detect_min_severity
        result = detect_min_severity(cwd=tmp_path)
        assert result is None or isinstance(result, str)

    def test_auto_detect_profile_returns_dict(self, tmp_path: Path) -> None:
        from security_pr_guardian.core.auto_detect import auto_detect_profile
        result = auto_detect_profile(cwd=tmp_path)
        assert isinstance(result, dict)
        assert "frameworks" in result
        assert "auth_libraries" in result
        assert "min_severity" in result

    def test_detect_frameworks_from_requirements_txt(self, tmp_path: Path) -> None:
        from security_pr_guardian.core.auto_detect import detect_frameworks
        (tmp_path / "requirements.txt").write_text("django>=3.2\n", encoding="utf-8")
        result = detect_frameworks(cwd=tmp_path)
        assert "django" in result

    def test_detect_auth_libraries_from_requirements_txt(self, tmp_path: Path) -> None:
        from security_pr_guardian.core.auto_detect import detect_auth_libraries
        (tmp_path / "requirements.txt").write_text("bcrypt==4.0\n", encoding="utf-8")
        result = detect_auth_libraries(cwd=tmp_path)
        assert "bcrypt" in result

    def test_detect_min_severity_from_bandit(self, tmp_path: Path) -> None:
        from security_pr_guardian.core.auto_detect import detect_min_severity
        (tmp_path / ".bandit").write_text("level = HIGH\n", encoding="utf-8")
        result = detect_min_severity(cwd=tmp_path)
        assert result == "high"

    def test_detect_frameworks_from_package_json(self, tmp_path: Path) -> None:
        from security_pr_guardian.core.auto_detect import detect_frameworks
        data = {"dependencies": {"express": "^4.18"}}
        (tmp_path / "package.json").write_text(json.dumps(data), encoding="utf-8")
        result = detect_frameworks(cwd=tmp_path)
        assert "express" in result

    def test_auto_detect_profile_combines_all(self, tmp_path: Path) -> None:
        from security_pr_guardian.core.auto_detect import auto_detect_profile
        (tmp_path / "requirements.txt").write_text("fastapi\nbcrypt\n", encoding="utf-8")
        (tmp_path / ".bandit").write_text("level = MEDIUM\n", encoding="utf-8")
        result = auto_detect_profile(cwd=tmp_path)
        assert "fastapi" in result["frameworks"]
        assert "bcrypt" in result["auth_libraries"]
        assert result["min_severity"] == "medium"
