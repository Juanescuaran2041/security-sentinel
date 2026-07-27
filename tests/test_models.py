"""Unit tests for domain models and AppConfig validation."""

import os

import pytest
from pydantic import ValidationError

from security_pr_guardian.core.models import (
    AnalysisResult,
    AppConfig,
    CandidateFinding,
    ConfirmedFinding,
    CVEFinding,
    DependencyChange,
    ErrorFinding,
    KBFragment,
    LLMVerdict,
    LogEvent,
    Recommendation,
    Severity,
    SEVERITY_ORDER,
    StaticAnalysisResult,
)


class TestSeverity:
    """Tests for Severity enum and SEVERITY_ORDER."""

    def test_valid_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_severity_order_critical_is_highest(self):
        assert SEVERITY_ORDER[Severity.CRITICAL] > SEVERITY_ORDER[Severity.HIGH]
        assert SEVERITY_ORDER[Severity.HIGH] > SEVERITY_ORDER[Severity.MEDIUM]
        assert SEVERITY_ORDER[Severity.MEDIUM] > SEVERITY_ORDER[Severity.LOW]
        assert SEVERITY_ORDER[Severity.LOW] > SEVERITY_ORDER[Severity.INFO]

    def test_severity_order_covers_all_values(self):
        for sev in Severity:
            assert sev in SEVERITY_ORDER


class TestCandidateFinding:
    """Tests for CandidateFinding model."""

    def _make_finding(self, **overrides):
        defaults = {
            "source": "static",
            "tipo_vulnerabilidad": "sql_injection",
            "archivo": "app.py",
            "linea_inicio": 10,
            "linea_fin": 12,
            "fragmento_codigo": "SELECT * FROM users WHERE id = " + "'{}'",
            "patron_detectado": "sql_concat",
            "severidad_inicial": Severity.HIGH,
        }
        defaults.update(overrides)
        return CandidateFinding(**defaults)

    def test_auto_generated_uuid(self):
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert f1.finding_id != f2.finding_id
        assert len(f1.finding_id) == 36  # UUID format

    def test_fragmento_codigo_max_length_500(self):
        # Exactly 500 chars should be fine
        self._make_finding(fragmento_codigo="x" * 500)

        # 501 chars should fail
        with pytest.raises(ValidationError, match="fragmento_codigo"):
            self._make_finding(fragmento_codigo="x" * 501)

    def test_source_literal_static(self):
        f = self._make_finding(source="static")
        assert f.source == "static"

    def test_source_literal_cve(self):
        f = self._make_finding(source="cve")
        assert f.source == "cve"

    def test_invalid_source_rejected(self):
        with pytest.raises(ValidationError):
            self._make_finding(source="invalid_source")

    def test_optional_fields_default_none(self):
        f = self._make_finding()
        assert f.cwe_id is None
        assert f.cve_id is None
        assert f.paquete is None
        assert f.version is None
        assert f.ecosistema is None


class TestRecommendation:
    """Tests for Recommendation model."""

    def test_basic_construction(self):
        r = Recommendation(
            descripcion="Use parameterized queries",
            codigo_corregido="cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
            referencia="https://owasp.org/sql-injection",
        )
        assert r.descripcion == "Use parameterized queries"
        assert r.codigo_corregido is not None
        assert r.referencia is not None

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            Recommendation(descripcion="Fix it")  # missing codigo_corregido, referencia


class TestLLMVerdict:
    """Tests for LLMVerdict model."""

    def _make_recommendation(self):
        return Recommendation(
            descripcion="Fix",
            codigo_corregido="fixed()",
            referencia="https://example.com",
        )

    def test_justificacion_min_length_50(self):
        # Exactly 50 chars should work
        LLMVerdict(
            es_explotable=True,
            severidad_ajustada=Severity.HIGH,
            justificacion="a" * 50,
            recomendacion=self._make_recommendation(),
        )

    def test_justificacion_too_short_raises(self):
        with pytest.raises(ValidationError, match="justificacion"):
            LLMVerdict(
                es_explotable=True,
                severidad_ajustada=Severity.HIGH,
                justificacion="too short",
                recomendacion=self._make_recommendation(),
            )

    def test_severity_enum_validation(self):
        with pytest.raises(ValidationError):
            LLMVerdict(
                es_explotable=False,
                severidad_ajustada="INVALID",
                justificacion="a" * 50,
                recomendacion=self._make_recommendation(),
            )


class TestConfirmedFinding:
    """Tests for ConfirmedFinding model."""

    def _make_finding(self, **overrides):
        defaults = {
            "finding_id": "abc-123",
            "source": "static",
            "tipo_vulnerabilidad": "xss",
            "archivo": "views.py",
            "linea_inicio": 1,
            "linea_fin": 5,
            "fragmento_codigo": "<script>alert(1)</script>",
            "severidad_ajustada": Severity.MEDIUM,
            "justificacion": "Exploitable reflected XSS",
            "recomendacion": Recommendation(
                descripcion="Escape output",
                codigo_corregido="escape(input)",
                referencia="https://owasp.org",
            ),
            "disposition": "incluido",
        }
        defaults.update(overrides)
        return ConfirmedFinding(**defaults)

    def test_valid_dispositions(self):
        for disp in ["incluido", "descartado", "no_evaluado"]:
            f = self._make_finding(disposition=disp)
            assert f.disposition == disp

    def test_invalid_disposition_rejected(self):
        with pytest.raises(ValidationError):
            self._make_finding(disposition="otro_valor")


class TestKBFragment:
    """Tests for KBFragment model."""

    def test_score_relevancia_bounds_valid(self):
        KBFragment(titulo="T", contenido="C", fuente="F", score_relevancia=0.0)
        KBFragment(titulo="T", contenido="C", fuente="F", score_relevancia=1.0)
        KBFragment(titulo="T", contenido="C", fuente="F", score_relevancia=0.5)

    def test_score_relevancia_below_zero_rejected(self):
        with pytest.raises(ValidationError, match="score_relevancia"):
            KBFragment(titulo="T", contenido="C", fuente="F", score_relevancia=-0.1)

    def test_score_relevancia_above_one_rejected(self):
        with pytest.raises(ValidationError, match="score_relevancia"):
            KBFragment(titulo="T", contenido="C", fuente="F", score_relevancia=1.1)


class TestAnalysisResult:
    """Tests for AnalysisResult model."""

    def _make_result(self, **overrides):
        defaults = {
            "repo": "user/repo",
            "pr_number": 42,
            "candidate_count": 5,
            "confirmed_count": 2,
            "discarded_count": 3,
            "not_evaluated_count": 0,
            "confirmed_findings": [],
            "diff_truncated": False,
            "dependency_limit_exceeded": False,
            "duration_seconds": 12.5,
            "model_id": "anthropic.claude-3-sonnet",
            "guardian_version": "0.1.0",
        }
        defaults.update(overrides)
        return AnalysisResult(**defaults)

    def test_auto_generated_uuid(self):
        r1 = self._make_result()
        r2 = self._make_result()
        assert r1.analysis_id != r2.analysis_id
        assert len(r1.analysis_id) == 36

    def test_auto_timestamp(self):
        r = self._make_result()
        assert r.timestamp_utc is not None
        assert r.timestamp_utc.tzinfo is not None


class TestDependencyChange:
    """Tests for DependencyChange model."""

    def test_basic_construction(self):
        d = DependencyChange(
            manifest_file="requirements.txt",
            package="requests",
            version="2.31.0",
            ecosystem="pip",
        )
        assert d.manifest_file == "requirements.txt"
        assert d.package == "requests"
        assert d.version == "2.31.0"
        assert d.ecosystem == "pip"


class TestLogEvent:
    """Tests for LogEvent model."""

    def test_auto_timestamp(self):
        evt = LogEvent(
            analysis_id="test-id",
            componente="Test",
            evento="started",
        )
        assert evt.timestamp is not None
        assert evt.timestamp.tzinfo is not None

    def test_duracion_ms_optional(self):
        evt = LogEvent(
            analysis_id="test-id",
            componente="Test",
            evento="done",
        )
        assert evt.duracion_ms is None

    def test_duracion_ms_set(self):
        evt = LogEvent(
            analysis_id="test-id",
            componente="Test",
            evento="done",
            duracion_ms=250,
        )
        assert evt.duracion_ms == 250


class TestStaticAnalysisResult:
    """Tests for StaticAnalysisResult model."""

    def test_default_empty_lists(self):
        r = StaticAnalysisResult()
        assert r.findings == []
        assert r.errores_parciales == []


class TestCVEFinding:
    """Tests for CVEFinding model."""

    def _make_cve(self, **overrides):
        defaults = {
            "cve_id": "CVE-2024-1234",
            "paquete": "lodash",
            "version": "4.17.20",
            "ecosistema": "npm",
            "severidad": "HIGH",
            "descripcion": "Prototype pollution",
            "referencias": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        }
        defaults.update(overrides)
        return CVEFinding(**defaults)

    def test_valid_severidad_literals(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
            f = self._make_cve(severidad=sev)
            assert f.severidad == sev

    def test_invalid_severidad_rejected(self):
        with pytest.raises(ValidationError):
            self._make_cve(severidad="INVALID")


class TestErrorFinding:
    """Tests for ErrorFinding model."""

    def _make_error(self, **overrides):
        defaults = {
            "tipo": "error_input",
            "paquete": "requests",
            "version": "2.31.0",
            "ecosistema": "pip",
            "error_descripcion": "Invalid package name",
        }
        defaults.update(overrides)
        return ErrorFinding(**defaults)

    def test_valid_tipo_literals(self):
        for tipo in ["error_input", "error_lookup", "limit_exceeded"]:
            f = self._make_error(tipo=tipo)
            assert f.tipo == tipo

    def test_invalid_tipo_rejected(self):
        with pytest.raises(ValidationError):
            self._make_error(tipo="unknown_error")


class TestAppConfig:
    """Tests for AppConfig validation logic."""

    def _clean_env(self, monkeypatch):
        """Remove env vars that could interfere with AppConfig.

        Also disables .env file loading so real credentials in the project's
        .env don't satisfy validation requirements during tests.
        """
        env_vars = [
            "GITHUB_TOKEN",
            "LLM_BACKEND",
            "BEDROCK_REGION",
            "BEDROCK_MODEL_ID",
            "OSV_TIMEOUT_SECONDS",
            "MAX_DIFF_LINES",
            "MAX_DEPENDENCIES",
        ]
        for var in env_vars:
            monkeypatch.delenv(var, raising=False)

        # Prevent pydantic-settings from reading the real .env file.
        # model_config is a plain dict on the class, so we can patch it directly.
        monkeypatch.setitem(AppConfig.model_config, "env_file", None)

    def _make_bedrock_config(self, **overrides):
        """Create a valid bedrock AppConfig kwargs dict."""
        defaults = {
            "github_token": "ghp_test_token_123",
            "llm_backend": "bedrock",
            "bedrock_region": "us-east-1",
            "bedrock_model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
        }
        defaults.update(overrides)
        return defaults

    def test_missing_github_token_raises(self, monkeypatch):
        self._clean_env(monkeypatch)
        with pytest.raises(ValidationError, match="github_token"):
            AppConfig(
                llm_backend="bedrock",
                bedrock_region="us-east-1",
                bedrock_model_id="model-id",
            )

    def test_bedrock_missing_region_raises(self, monkeypatch):
        self._clean_env(monkeypatch)
        with pytest.raises(ValueError, match="bedrock_region"):
            AppConfig(
                github_token="ghp_token",
                llm_backend="bedrock",
                bedrock_model_id="model-id",
            )

    def test_bedrock_missing_model_id_raises(self, monkeypatch):
        self._clean_env(monkeypatch)
        with pytest.raises(ValueError, match="bedrock_region"):
            AppConfig(
                github_token="ghp_token",
                llm_backend="bedrock",
                bedrock_region="us-east-1",
            )

    def test_osv_timeout_zero_raises(self, monkeypatch):
        self._clean_env(monkeypatch)
        with pytest.raises(ValidationError, match="osv_timeout_seconds"):
            AppConfig(**self._make_bedrock_config(osv_timeout_seconds=0))

    def test_osv_timeout_301_raises(self, monkeypatch):
        self._clean_env(monkeypatch)
        with pytest.raises(ValidationError, match="osv_timeout_seconds"):
            AppConfig(**self._make_bedrock_config(osv_timeout_seconds=301))

    def test_max_diff_lines_zero_raises(self, monkeypatch):
        self._clean_env(monkeypatch)
        with pytest.raises(ValidationError, match="max_diff_lines"):
            AppConfig(**self._make_bedrock_config(max_diff_lines=0))

    def test_max_diff_lines_10001_raises(self, monkeypatch):
        self._clean_env(monkeypatch)
        with pytest.raises(ValidationError, match="max_diff_lines"):
            AppConfig(**self._make_bedrock_config(max_diff_lines=10001))

    def test_max_dependencies_zero_raises(self, monkeypatch):
        self._clean_env(monkeypatch)
        with pytest.raises(ValidationError, match="max_dependencies"):
            AppConfig(**self._make_bedrock_config(max_dependencies=0))

    def test_max_dependencies_1001_raises(self, monkeypatch):
        self._clean_env(monkeypatch)
        with pytest.raises(ValidationError, match="max_dependencies"):
            AppConfig(**self._make_bedrock_config(max_dependencies=1001))

    def test_valid_bedrock_config_succeeds(self, monkeypatch):
        self._clean_env(monkeypatch)
        cfg = AppConfig(**self._make_bedrock_config())
        assert cfg.llm_backend == "bedrock"
        assert cfg.bedrock_region == "us-east-1"

    def test_default_values_applied(self, monkeypatch):
        self._clean_env(monkeypatch)
        cfg = AppConfig(**self._make_bedrock_config())
        assert cfg.osv_timeout_seconds == 10
        assert cfg.max_diff_lines == 10000
        assert cfg.max_dependencies == 50
        assert cfg.llm_backend == "bedrock"

    def test_env_vars_override_constructor_defaults(self, monkeypatch):
        self._clean_env(monkeypatch)
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")
        monkeypatch.setenv("LLM_BACKEND", "bedrock")
        monkeypatch.setenv("BEDROCK_REGION", "eu-west-1")
        monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku")
        monkeypatch.setenv("OSV_TIMEOUT_SECONDS", "30")

        cfg = AppConfig()
        assert cfg.github_token == "ghp_from_env"
        assert cfg.bedrock_region == "eu-west-1"
        assert cfg.osv_timeout_seconds == 30
