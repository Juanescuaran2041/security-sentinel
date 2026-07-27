"""Tests unitarios del AutoDetector — tarea 14.8.

Cubre:
- Detección correcta de frameworks desde requirements.txt y package.json
- Detección de librerías de auth
- No-crash cuando los archivos no existen
- Detección desde pyproject.toml (PEP 621 y Poetry)
- Detección de severidad desde .bandit
- Directorio vacío retorna DetectionResult con listas vacías
"""

import json
from pathlib import Path

import pytest

from security_pr_guardian.core.auto_detect import AutoDetector, DetectionResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# 14.8.1 — No-crash cuando no existen archivos
# ---------------------------------------------------------------------------


class TestNoFilesPresent:
    def test_returns_detection_result(self, tmp_path):
        result = AutoDetector(cwd=tmp_path).detect()
        assert isinstance(result, DetectionResult)

    def test_frameworks_empty(self, tmp_path):
        result = AutoDetector(cwd=tmp_path).detect()
        assert result.frameworks == []

    def test_auth_libraries_empty(self, tmp_path):
        result = AutoDetector(cwd=tmp_path).detect()
        assert result.auth_libraries == []

    def test_min_severity_none(self, tmp_path):
        result = AutoDetector(cwd=tmp_path).detect()
        assert result.min_severity is None

    def test_no_exception_on_missing_files(self, tmp_path):
        AutoDetector(cwd=tmp_path).detect()  # no debe lanzar


# ---------------------------------------------------------------------------
# 14.8.2 — Detección desde requirements.txt
# ---------------------------------------------------------------------------


class TestRequirementsTxt:
    def test_detects_django_framework(self, tmp_path):
        _write(tmp_path / "requirements.txt", "django>=3.2\nrequests==2.28\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert "django" in result.frameworks

    def test_detects_fastapi_framework(self, tmp_path):
        _write(tmp_path / "requirements.txt", "fastapi\nuvicorn\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert "fastapi" in result.frameworks

    def test_detects_flask_framework(self, tmp_path):
        _write(tmp_path / "requirements.txt", "flask==2.3.0\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert "flask" in result.frameworks

    def test_detects_bcrypt_auth_library(self, tmp_path):
        _write(tmp_path / "requirements.txt", "bcrypt==4.0.1\ndjango\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert "bcrypt" in result.auth_libraries

    def test_detects_passlib_auth_library(self, tmp_path):
        _write(tmp_path / "requirements.txt", "passlib[bcrypt]\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert "passlib" in result.auth_libraries

    def test_ignores_comments(self, tmp_path):
        _write(tmp_path / "requirements.txt", "# comentario\ndjango\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert "django" in result.frameworks

    def test_ignores_pip_options(self, tmp_path):
        _write(tmp_path / "requirements.txt", "-r base.txt\nflask\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert "flask" in result.frameworks

    def test_unknown_packages_not_in_frameworks(self, tmp_path):
        _write(tmp_path / "requirements.txt", "some-random-package==1.0\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert result.frameworks == []

    def test_no_exception_on_missing_file(self, tmp_path):
        # No hay requirements.txt
        AutoDetector(cwd=tmp_path).detect()


# ---------------------------------------------------------------------------
# 14.8.3 — Detección desde package.json
# ---------------------------------------------------------------------------


class TestPackageJson:
    def test_detects_react_framework(self, tmp_path):
        data = {"dependencies": {"react": "^18.0.0", "react-dom": "^18.0.0"}}
        _write(tmp_path / "package.json", json.dumps(data))
        result = AutoDetector(cwd=tmp_path).detect()
        assert "react" in result.frameworks

    def test_detects_express_framework(self, tmp_path):
        data = {"dependencies": {"express": "^4.18"}}
        _write(tmp_path / "package.json", json.dumps(data))
        result = AutoDetector(cwd=tmp_path).detect()
        assert "express" in result.frameworks

    def test_detects_from_dev_dependencies(self, tmp_path):
        data = {"devDependencies": {"next": "^14.0.0"}}
        _write(tmp_path / "package.json", json.dumps(data))
        result = AutoDetector(cwd=tmp_path).detect()
        assert "next" in result.frameworks

    def test_detects_passport_auth_library(self, tmp_path):
        data = {"dependencies": {"passport": "^0.6", "express": "^4"}}
        _write(tmp_path / "package.json", json.dumps(data))
        result = AutoDetector(cwd=tmp_path).detect()
        assert "passport" in result.auth_libraries

    def test_detects_jsonwebtoken_auth_library(self, tmp_path):
        data = {"dependencies": {"jsonwebtoken": "^9.0"}}
        _write(tmp_path / "package.json", json.dumps(data))
        result = AutoDetector(cwd=tmp_path).detect()
        assert "jsonwebtoken" in result.auth_libraries

    def test_no_exception_on_invalid_json(self, tmp_path):
        _write(tmp_path / "package.json", "{ invalid json }")
        AutoDetector(cwd=tmp_path).detect()

    def test_no_exception_on_missing_file(self, tmp_path):
        AutoDetector(cwd=tmp_path).detect()

    def test_empty_sections_return_empty(self, tmp_path):
        data = {"dependencies": {}, "devDependencies": {}}
        _write(tmp_path / "package.json", json.dumps(data))
        result = AutoDetector(cwd=tmp_path).detect()
        assert result.frameworks == []


# ---------------------------------------------------------------------------
# 14.8.4 — Detección desde pyproject.toml
# ---------------------------------------------------------------------------


class TestPyprojectToml:
    def test_detects_django_pep621(self, tmp_path):
        toml = '[project]\ndependencies = ["django>=4.0", "pydantic"]\n'
        _write(tmp_path / "pyproject.toml", toml)
        result = AutoDetector(cwd=tmp_path).detect()
        assert "django" in result.frameworks

    def test_detects_bcrypt_pep621(self, tmp_path):
        toml = '[project]\ndependencies = ["bcrypt>=4.0"]\n'
        _write(tmp_path / "pyproject.toml", toml)
        result = AutoDetector(cwd=tmp_path).detect()
        assert "bcrypt" in result.auth_libraries

    def test_detects_poetry_dependencies(self, tmp_path):
        toml = (
            "[tool.poetry.dependencies]\n"
            'python = "^3.11"\n'
            'fastapi = "*"\n'
            'bcrypt = "^4.0"\n'
        )
        _write(tmp_path / "pyproject.toml", toml)
        result = AutoDetector(cwd=tmp_path).detect()
        assert "fastapi" in result.frameworks
        assert "bcrypt" in result.auth_libraries

    def test_python_not_in_frameworks(self, tmp_path):
        toml = '[tool.poetry.dependencies]\npython = "^3.11"\ndjango = "^4"\n'
        _write(tmp_path / "pyproject.toml", toml)
        result = AutoDetector(cwd=tmp_path).detect()
        assert "python" not in result.frameworks

    def test_no_exception_on_invalid_toml(self, tmp_path):
        _write(tmp_path / "pyproject.toml", ": invalid toml [[\n")
        AutoDetector(cwd=tmp_path).detect()

    def test_no_exception_on_missing_file(self, tmp_path):
        AutoDetector(cwd=tmp_path).detect()


# ---------------------------------------------------------------------------
# 14.8.5 — Detección de severidad desde .bandit
# ---------------------------------------------------------------------------


class TestDetectMinSeverity:
    def test_detects_medium_from_bandit(self, tmp_path):
        _write(tmp_path / ".bandit", "[bandit]\nlevel = MEDIUM\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert result.min_severity == "medium"

    def test_detects_high_from_bandit(self, tmp_path):
        _write(tmp_path / ".bandit", "level = HIGH\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert result.min_severity == "high"

    def test_detects_low_from_bandit(self, tmp_path):
        _write(tmp_path / ".bandit", "level = low\n")
        result = AutoDetector(cwd=tmp_path).detect()
        assert result.min_severity == "low"

    def test_returns_none_when_no_linter_config(self, tmp_path):
        result = AutoDetector(cwd=tmp_path).detect()
        assert result.min_severity is None

    def test_no_exception_on_unreadable_bandit(self, tmp_path, monkeypatch):
        bandit = tmp_path / ".bandit"
        _write(bandit, "level = HIGH")
        # Simular OSError al leer
        original_read = Path.read_text

        def bad_read(self, *args, **kwargs):
            if self.name == ".bandit":
                raise OSError("permission denied")
            return original_read(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", bad_read)
        AutoDetector(cwd=tmp_path).detect()  # no debe lanzar


# ---------------------------------------------------------------------------
# 14.8.6 — Combinación de múltiples manifiestos
# ---------------------------------------------------------------------------


class TestMultipleManifests:
    def test_combines_requirements_and_package_json(self, tmp_path):
        _write(tmp_path / "requirements.txt", "django\n")
        _write(tmp_path / "package.json", json.dumps({"dependencies": {"react": "^18"}}))
        result = AutoDetector(cwd=tmp_path).detect()
        assert "django" in result.frameworks
        assert "react" in result.frameworks

    def test_deduplicates_same_package_from_multiple_sources(self, tmp_path):
        _write(tmp_path / "requirements.txt", "bcrypt\n")
        toml = '[project]\ndependencies = ["bcrypt"]\n'
        _write(tmp_path / "pyproject.toml", toml)
        result = AutoDetector(cwd=tmp_path).detect()
        # bcrypt debe aparecer una sola vez
        assert result.auth_libraries.count("bcrypt") == 1
