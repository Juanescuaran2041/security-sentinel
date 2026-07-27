"""Property-based tests para la salida JSON del CLI.

**Validates: Requirements 1.8**

Verifica Property 15: La salida JSON del CLI siempre es JSON parseable válido.
Usa st.builds(AnalysisResult, ...) para generar instancias aleatorias y verifica
que render_json_output produce JSON válido con las claves requeridas.
"""

from __future__ import annotations

import io
import json
import sys
from datetime import datetime, timezone
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from security_pr_guardian.cli.output import render_json_output
from security_pr_guardian.core.models import (
    AnalysisResult,
    ConfirmedFinding,
    Recommendation,
    Severity,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

recommendation_strategy = st.builds(
    Recommendation,
    descripcion=st.text(min_size=1, max_size=50),
    codigo_corregido=st.text(min_size=1, max_size=50),
    referencia=st.text(min_size=1, max_size=50),
)

confirmed_finding_strategy = st.builds(
    ConfirmedFinding,
    finding_id=st.text(min_size=1, max_size=50),
    source=st.sampled_from(["static", "cve"]),
    tipo_vulnerabilidad=st.text(min_size=1, max_size=50),
    archivo=st.text(min_size=1, max_size=50),
    linea_inicio=st.integers(min_value=1, max_value=10000),
    linea_fin=st.integers(min_value=1, max_value=10000),
    fragmento_codigo=st.text(min_size=1, max_size=50),
    cwe_id=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
    cve_id=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
    severidad_ajustada=st.sampled_from(list(Severity)),
    justificacion=st.text(min_size=1, max_size=200),
    recomendacion=recommendation_strategy,
    disposition=st.sampled_from(["incluido", "descartado", "no_evaluado"]),
)

analysis_result_strategy = st.builds(
    AnalysisResult,
    analysis_id=st.text(min_size=1, max_size=50),
    repo=st.text(min_size=1, max_size=50),
    pr_number=st.integers(min_value=1, max_value=100000),
    candidate_count=st.integers(min_value=0, max_value=1000),
    confirmed_count=st.integers(min_value=0, max_value=1000),
    discarded_count=st.integers(min_value=0, max_value=1000),
    not_evaluated_count=st.integers(min_value=0, max_value=1000),
    confirmed_findings=st.lists(confirmed_finding_strategy, min_size=0, max_size=5),
    diff_truncated=st.booleans(),
    dependency_limit_exceeded=st.booleans(),
    comment_id=st.one_of(st.none(), st.text(min_size=1, max_size=50)),
    duration_seconds=st.floats(min_value=0.0, max_value=3600.0),
    model_id=st.text(min_size=1, max_size=50),
    guardian_version=st.text(min_size=1, max_size=20),
    timestamp_utc=st.datetimes(timezones=st.just(timezone.utc)),
)


# ---------------------------------------------------------------------------
# Property Test
# ---------------------------------------------------------------------------


class TestCLIJsonOutputProperty:
    """Property 15: La salida JSON del CLI siempre es JSON parseable válido."""

    @settings(max_examples=100)
    @given(result=analysis_result_strategy)
    def test_json_output_always_parseable_with_required_keys(
        self, result: AnalysisResult
    ) -> None:
        """render_json_output siempre produce JSON válido con claves requeridas."""
        buf = io.StringIO()
        with patch.object(sys, "stdout", buf):
            render_json_output(result)

        output = buf.getvalue()

        # Must be valid JSON
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

        # Must contain required keys
        required_keys = [
            "analysis_id",
            "confirmed_count",
            "discarded_count",
            "confirmed_findings",
            "diff_truncated",
        ]
        for key in required_keys:
            assert key in parsed, f"Missing required key: {key}"
