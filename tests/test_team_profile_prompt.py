"""Tests unitarios del prompt con TeamProfile — tarea 14.7.

Cubre:
- Sección ## Perfil del Equipo presente cuando el perfil tiene contenido
- Sección ausente cuando el perfil está vacío (todos defaults)
- allowed_patterns formateados correctamente en el prompt
- Orden: sección de perfil aparece ANTES que ## Contexto de la Base de Conocimiento
- team_profile=None produce el mismo resultado que perfil vacío
"""

import pytest

from security_pr_guardian.adapters.llm.bedrock_adapter import (
    _build_team_profile_section,
    _build_user_prompt,
)
from security_pr_guardian.core.models import (
    AllowedPattern,
    CandidateFinding,
    KBFragment,
    Severity,
    TeamProfile,
)


# ---------------------------------------------------------------------------
# Fixture base
# ---------------------------------------------------------------------------


@pytest.fixture
def finding():
    return CandidateFinding(
        source="static",
        tipo_vulnerabilidad="SQL Injection",
        archivo="app/db.py",
        linea_inicio=10,
        linea_fin=10,
        fragmento_codigo='query = f"SELECT * FROM users WHERE id={uid}"',
        patron_detectado="f-string in SQL",
        cwe_id="CWE-89",
        severidad_inicial=Severity.HIGH,
    )


@pytest.fixture
def kb_fragment():
    return KBFragment(
        titulo="OWASP SQL Injection",
        contenido="Avoid dynamic queries...",
        fuente="owasp.org",
        score_relevancia=0.9,
    )


@pytest.fixture
def full_profile():
    return TeamProfile(
        frameworks=["django", "react"],
        auth_libraries=["bcrypt"],
        allowed_patterns=[
            AllowedPattern(cwe_id="CWE-502", razon="pickle en cache interno"),
            AllowedPattern(cwe_id="CWE-327", razon="md5 para ETags no criptográficos"),
        ],
        min_severity=Severity.MEDIUM,
        custom_exceptions=["logs internos con datos sensibles permitidos"],
    )


# ---------------------------------------------------------------------------
# 14.7.1 — _build_team_profile_section
# ---------------------------------------------------------------------------


class TestBuildTeamProfileSection:
    def test_empty_profile_returns_empty_string(self):
        assert _build_team_profile_section(TeamProfile()) == ""

    def test_frameworks_present(self, full_profile):
        section = _build_team_profile_section(full_profile)
        assert "## Perfil del Equipo" in section
        assert "django" in section
        assert "react" in section

    def test_auth_libraries_present(self, full_profile):
        section = _build_team_profile_section(full_profile)
        assert "bcrypt" in section

    def test_allowed_patterns_formatted(self, full_profile):
        section = _build_team_profile_section(full_profile)
        assert "CWE-502" in section
        assert "pickle en cache interno" in section
        assert "CWE-327" in section
        assert "md5 para ETags" in section

    def test_custom_exceptions_present(self, full_profile):
        section = _build_team_profile_section(full_profile)
        assert "logs internos" in section

    def test_min_severity_present(self, full_profile):
        section = _build_team_profile_section(full_profile)
        assert "medium" in section.lower()

    def test_profile_only_frameworks_generates_section(self):
        """Solo frameworks ya es suficiente para generar la sección."""
        profile = TeamProfile(frameworks=["fastapi"])
        section = _build_team_profile_section(profile)
        assert "## Perfil del Equipo" in section
        assert "fastapi" in section

    def test_profile_only_auth_libs_generates_section(self):
        profile = TeamProfile(auth_libraries=["passlib"])
        section = _build_team_profile_section(profile)
        assert "## Perfil del Equipo" in section

    def test_profile_only_custom_exceptions_generates_section(self):
        profile = TeamProfile(custom_exceptions=["excepción custom"])
        section = _build_team_profile_section(profile)
        assert "## Perfil del Equipo" in section


# ---------------------------------------------------------------------------
# 14.7.2 — _build_user_prompt con team_profile
# ---------------------------------------------------------------------------


class TestBuildUserPromptWithTeamProfile:
    def test_section_absent_when_profile_none(self, finding):
        prompt = _build_user_prompt(finding, [], team_profile=None)
        assert "## Perfil del Equipo" not in prompt

    def test_section_absent_when_profile_empty(self, finding):
        prompt = _build_user_prompt(finding, [], team_profile=TeamProfile())
        assert "## Perfil del Equipo" not in prompt

    def test_section_present_when_profile_has_content(self, finding, full_profile):
        prompt = _build_user_prompt(finding, [], team_profile=full_profile)
        assert "## Perfil del Equipo" in prompt

    def test_profile_section_before_kb_section(self, finding, kb_fragment, full_profile):
        prompt = _build_user_prompt(finding, [kb_fragment], team_profile=full_profile)
        idx_profile = prompt.index("## Perfil del Equipo")
        idx_kb = prompt.index("## Contexto de la Base de Conocimiento")
        assert idx_profile < idx_kb

    def test_allowed_patterns_in_prompt(self, finding, full_profile):
        prompt = _build_user_prompt(finding, [], team_profile=full_profile)
        assert "CWE-502" in prompt
        assert "pickle en cache interno" in prompt

    def test_finding_section_always_present(self, finding, full_profile):
        prompt = _build_user_prompt(finding, [], team_profile=full_profile)
        assert "## Hallazgo Candidato" in prompt
        assert "CWE-89" in prompt

    def test_kb_section_absent_when_empty(self, finding, full_profile):
        prompt = _build_user_prompt(finding, [], team_profile=full_profile)
        assert "## Contexto de la Base de Conocimiento" not in prompt

    def test_kb_section_present_when_provided(self, finding, kb_fragment):
        prompt = _build_user_prompt(finding, [kb_fragment], team_profile=None)
        assert "## Contexto de la Base de Conocimiento" in prompt

    def test_profile_none_and_empty_produce_same_result(self, finding):
        prompt_none = _build_user_prompt(finding, [], team_profile=None)
        prompt_empty = _build_user_prompt(finding, [], team_profile=TeamProfile())
        assert prompt_none == prompt_empty
