"""Tests unitarios del TeamProfileLoader — tarea 14.6.

Cubre:
- Carga correcta desde YAML válido (con clave raíz team_profile y sin ella)
- Degradación a defaults en YAML inválido
- Degradación a defaults cuando el archivo no existe
- Warning emitido en ambos casos de falla (StructuredLogger y stdlib logger)
- Ningún test lanza excepción no manejada
"""

import io
import logging
import uuid
from pathlib import Path

import pytest

from security_pr_guardian.core.logger import StructuredLogger
from security_pr_guardian.core.models import AllowedPattern, Severity, TeamProfile
from security_pr_guardian.core.team_profile import PROFILE_FILENAME, TeamProfileLoader


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_logger() -> tuple[StructuredLogger, io.StringIO]:
    """Retorna un StructuredLogger que escribe en un buffer de string."""
    buf = io.StringIO()
    logger = StructuredLogger(analysis_id=str(uuid.uuid4()), output=buf)
    return logger, buf


def _write_profile(tmp_path: Path, content: str) -> Path:
    profile = tmp_path / PROFILE_FILENAME
    profile.write_text(content, encoding="utf-8")
    return profile


# ---------------------------------------------------------------------------
# 14.6.1 — Archivo ausente → defaults sin error
# ---------------------------------------------------------------------------


class TestFileAbsent:
    def test_returns_default_profile(self, tmp_path):
        loader = TeamProfileLoader(cwd=tmp_path)
        profile = loader.load()
        assert profile == TeamProfile()

    def test_no_exception_raised(self, tmp_path):
        loader = TeamProfileLoader(cwd=tmp_path)
        # No debe lanzar nada
        loader.load()

    def test_no_structured_warning_when_file_absent(self, tmp_path):
        """Archivo ausente es comportamiento esperado, no emite warning."""
        logger, buf = _make_logger()
        loader = TeamProfileLoader(cwd=tmp_path, logger=logger)
        loader.load()
        assert buf.getvalue() == ""


# ---------------------------------------------------------------------------
# 14.6.2 — YAML válido con clave raíz team_profile
# ---------------------------------------------------------------------------


class TestValidYamlWithRootKey:
    YAML = """\
team_profile:
  frameworks:
    - django
    - fastapi
  auth_libraries:
    - bcrypt
  allowed_patterns:
    - cwe_id: CWE-502
      razon: pickle en cache interno
  min_severity: high
  custom_exceptions:
    - md5 para ETags
"""

    def test_frameworks_parsed(self, tmp_path):
        _write_profile(tmp_path, self.YAML)
        profile = TeamProfileLoader(cwd=tmp_path).load()
        assert "django" in profile.frameworks
        assert "fastapi" in profile.frameworks

    def test_auth_libraries_parsed(self, tmp_path):
        _write_profile(tmp_path, self.YAML)
        profile = TeamProfileLoader(cwd=tmp_path).load()
        assert profile.auth_libraries == ["bcrypt"]

    def test_allowed_patterns_parsed(self, tmp_path):
        _write_profile(tmp_path, self.YAML)
        profile = TeamProfileLoader(cwd=tmp_path).load()
        assert len(profile.allowed_patterns) == 1
        assert profile.allowed_patterns[0].cwe_id == "CWE-502"
        assert "cache" in profile.allowed_patterns[0].razon

    def test_min_severity_parsed(self, tmp_path):
        _write_profile(tmp_path, self.YAML)
        profile = TeamProfileLoader(cwd=tmp_path).load()
        assert profile.min_severity == Severity.HIGH

    def test_custom_exceptions_parsed(self, tmp_path):
        _write_profile(tmp_path, self.YAML)
        profile = TeamProfileLoader(cwd=tmp_path).load()
        assert "md5 para ETags" in profile.custom_exceptions

    def test_no_warning_emitted(self, tmp_path):
        _write_profile(tmp_path, self.YAML)
        logger, buf = _make_logger()
        TeamProfileLoader(cwd=tmp_path, logger=logger).load()
        assert buf.getvalue() == ""


# ---------------------------------------------------------------------------
# 14.6.3 — YAML válido sin clave raíz (campos directos)
# ---------------------------------------------------------------------------


class TestValidYamlFlat:
    YAML = """\
frameworks:
  - flask
  - react
min_severity: medium
"""

    def test_frameworks_parsed_flat(self, tmp_path):
        _write_profile(tmp_path, self.YAML)
        profile = TeamProfileLoader(cwd=tmp_path).load()
        assert "flask" in profile.frameworks
        assert "react" in profile.frameworks

    def test_min_severity_parsed_flat(self, tmp_path):
        _write_profile(tmp_path, self.YAML)
        profile = TeamProfileLoader(cwd=tmp_path).load()
        assert profile.min_severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# 14.6.4 — YAML inválido → defaults + warning
# ---------------------------------------------------------------------------


class TestInvalidYaml:
    INVALID_YAML = ": bad: [unclosed\n"

    def test_returns_default_profile(self, tmp_path):
        _write_profile(tmp_path, self.INVALID_YAML)
        profile = TeamProfileLoader(cwd=tmp_path).load()
        assert profile == TeamProfile()

    def test_no_exception_raised(self, tmp_path):
        _write_profile(tmp_path, self.INVALID_YAML)
        TeamProfileLoader(cwd=tmp_path).load()  # no debe lanzar

    def test_structured_warning_emitted(self, tmp_path):
        _write_profile(tmp_path, self.INVALID_YAML)
        logger, buf = _make_logger()
        TeamProfileLoader(cwd=tmp_path, logger=logger).load()
        output = buf.getvalue()
        assert "team_profile_warning" in output

    def test_stdlib_warning_emitted(self, tmp_path, caplog):
        _write_profile(tmp_path, self.INVALID_YAML)
        with caplog.at_level(logging.WARNING, logger="security_pr_guardian.core.team_profile"):
            TeamProfileLoader(cwd=tmp_path).load()
        assert any("team_profile" in r.message.lower() or "yaml" in r.message.lower()
                   for r in caplog.records)


# ---------------------------------------------------------------------------
# 14.6.5 — Campos con tipos incorrectos → defaults + warning
# ---------------------------------------------------------------------------


class TestInvalidFieldTypes:
    YAML_BAD_TYPES = """\
team_profile:
  frameworks: not_a_list
  min_severity: INVALID_VALUE
"""

    def test_returns_default_profile(self, tmp_path):
        _write_profile(tmp_path, self.YAML_BAD_TYPES)
        profile = TeamProfileLoader(cwd=tmp_path).load()
        assert profile == TeamProfile()

    def test_no_exception_raised(self, tmp_path):
        _write_profile(tmp_path, self.YAML_BAD_TYPES)
        TeamProfileLoader(cwd=tmp_path).load()

    def test_warning_emitted(self, tmp_path):
        _write_profile(tmp_path, self.YAML_BAD_TYPES)
        logger, buf = _make_logger()
        TeamProfileLoader(cwd=tmp_path, logger=logger).load()
        assert "team_profile_warning" in buf.getvalue()


# ---------------------------------------------------------------------------
# 14.6.6 — Archivo vacío → defaults sin warning
# ---------------------------------------------------------------------------


class TestEmptyFile:
    def test_returns_default_profile(self, tmp_path):
        _write_profile(tmp_path, "")
        profile = TeamProfileLoader(cwd=tmp_path).load()
        assert profile == TeamProfile()

    def test_no_exception_raised(self, tmp_path):
        _write_profile(tmp_path, "")
        TeamProfileLoader(cwd=tmp_path).load()
