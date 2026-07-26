"""Property-based tests for BedrockAdapter.

Property 10 (task 6.5): JSON invalido del LLM siempre produce no_evaluado.
Property 6 (task 6.6): severidad_ajustada siempre es un valor valido del enum Severity.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from security_pr_guardian.adapters.llm.bedrock_adapter import (
    BedrockAdapter,
    _parse_llm_response,
    _make_no_evaluado_verdict,
)
from security_pr_guardian.core.models import (
    CandidateFinding,
    ConfirmedFinding,
    KBFragment,
    LLMVerdict,
    Recommendation,
    Severity,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

severity_st = st.sampled_from([s.value for s in Severity])

valid_recommendation_st = st.fixed_dictionaries({
    "descripcion": st.text(min_size=1, max_size=200),
    "codigo_corregido": st.text(min_size=0, max_size=500),
    "referencia": st.text(min_size=0, max_size=200),
})

# Strategy for dicts that are missing at least one required field
_REQUIRED_KEYS = ["es_explotable", "severidad_ajustada", "justificacion", "recomendacion"]


@st.composite
def invalid_json_dict_st(draw):
    """Generate dicts that are missing at least one required LLMVerdict field."""
    # Pick which fields to include (must be missing at least one)
    included = draw(st.lists(
        st.sampled_from(_REQUIRED_KEYS),
        min_size=0,
        max_size=len(_REQUIRED_KEYS) - 1,
        unique=True,
    ))
    result = {}
    if "es_explotable" in included:
        result["es_explotable"] = draw(st.booleans())
    if "severidad_ajustada" in included:
        result["severidad_ajustada"] = draw(severity_st)
    if "justificacion" in included:
        result["justificacion"] = draw(st.text(min_size=50, max_size=200))
    if "recomendacion" in included:
        result["recomendacion"] = draw(valid_recommendation_st)
    # Add some random extra keys to make it more realistic
    extra_keys = draw(st.dictionaries(
        st.text(min_size=1, max_size=20).filter(lambda k: k not in _REQUIRED_KEYS),
        st.text(min_size=0, max_size=50),
        max_size=3,
    ))
    result.update(extra_keys)
    return result


finding_st = st.builds(
    CandidateFinding,
    finding_id=st.text(min_size=1, max_size=36).map(lambda s: s or "id"),
    source=st.just("static"),
    tipo_vulnerabilidad=st.text(min_size=1, max_size=50),
    archivo=st.text(min_size=1, max_size=100),
    linea_inicio=st.integers(min_value=1, max_value=10000),
    linea_fin=st.integers(min_value=1, max_value=10000),
    fragmento_codigo=st.text(min_size=1, max_size=500),
    patron_detectado=st.text(min_size=1, max_size=100),
    cwe_id=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
    cve_id=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
    severidad_inicial=st.sampled_from(list(Severity)),
)


# ---------------------------------------------------------------------------
# Property 10: JSON invalido del LLM siempre produce no_evaluado
# Validates: Requirements 5.8
# ---------------------------------------------------------------------------


class TestProperty10InvalidJsonProducesNoEvaluado:
    """JSON invalido del LLM siempre produce disposition no_evaluado."""

    @settings(max_examples=100)
    @given(raw_text=st.text(min_size=0, max_size=1000))
    def test_arbitrary_text_produces_no_evaluado_or_valid_verdict(self, raw_text):
        """Any arbitrary text that isn't valid LLM JSON should raise ValueError."""
        # If it happens to be valid JSON with all fields, that's fine — skip it.
        try:
            data = json.loads(raw_text)
            if isinstance(data, dict) and all(k in data for k in _REQUIRED_KEYS):
                assume(False)  # skip valid cases
        except (json.JSONDecodeError, ValueError):
            pass

        # The parser should raise for invalid input
        with pytest.raises((json.JSONDecodeError, ValueError)):
            _parse_llm_response(raw_text)

    @settings(max_examples=100)
    @given(incomplete_dict=invalid_json_dict_st())
    def test_incomplete_dict_produces_parse_error(self, incomplete_dict):
        """A JSON dict missing required fields always raises ValueError."""
        raw_text = json.dumps(incomplete_dict)
        with pytest.raises(ValueError):
            _parse_llm_response(raw_text)

    @settings(max_examples=100)
    @given(raw_text=st.text(min_size=0, max_size=500))
    @pytest.mark.asyncio
    async def test_bedrock_adapter_returns_no_evaluado_on_invalid_json(self, raw_text):
        """BedrockAdapter.evaluate_finding returns no_evaluado verdict for invalid LLM output."""
        # Skip if text happens to be valid
        try:
            data = json.loads(raw_text)
            if isinstance(data, dict) and all(k in data for k in _REQUIRED_KEYS):
                assume(False)
        except (json.JSONDecodeError, ValueError):
            pass

        mock_response = {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": raw_text}],
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 10, "outputTokens": 10},
        }

        with patch("security_pr_guardian.adapters.llm.bedrock_adapter.boto3") as mock_boto3:
            mock_client = MagicMock()
            mock_boto3.client.return_value = mock_client
            mock_client.converse.return_value = mock_response

            adapter = BedrockAdapter(region="us-east-1", model_id="test-model")
            finding = CandidateFinding(
                source="static",
                tipo_vulnerabilidad="test",
                archivo="test.py",
                linea_inicio=1,
                linea_fin=1,
                fragmento_codigo="x = 1",
                patron_detectado="test",
                severidad_inicial=Severity.HIGH,
            )

            verdict = await adapter.evaluate_finding(finding, [])

            # Must be marked as non-exploitable with INFO severity
            assert verdict.es_explotable is False
            assert verdict.severidad_ajustada == Severity.INFO
            assert "invalida" in verdict.justificacion or "No se pudo evaluar" in verdict.justificacion


# ---------------------------------------------------------------------------
# Property 6: severidad_ajustada siempre es un valor valido del enum Severity
# Validates: Requirements 5.4
# ---------------------------------------------------------------------------


class TestProperty6SeveridadAjustadaAlwaysValid:
    """severidad_ajustada in any LLMVerdict is always a valid Severity enum value."""

    @settings(max_examples=100)
    @given(severity=severity_st)
    def test_valid_severity_parses_correctly(self, severity):
        """Any valid severity string from the enum parses without error."""
        data = json.dumps({
            "es_explotable": True,
            "severidad_ajustada": severity,
            "justificacion": "A" * 60,
            "recomendacion": {
                "descripcion": "fix it",
                "codigo_corregido": "code",
                "referencia": "ref",
            },
        })
        verdict = _parse_llm_response(data)
        assert verdict.severidad_ajustada in list(Severity)
        assert verdict.severidad_ajustada.value == severity

    @settings(max_examples=100)
    @given(
        invalid_severity=st.text(min_size=1, max_size=50).filter(
            lambda s: s not in [sev.value for sev in Severity]
        )
    )
    def test_invalid_severity_raises_value_error(self, invalid_severity):
        """Any string not in the Severity enum raises ValueError during parsing."""
        data = json.dumps({
            "es_explotable": True,
            "severidad_ajustada": invalid_severity,
            "justificacion": "A" * 60,
            "recomendacion": {
                "descripcion": "fix it",
                "codigo_corregido": "code",
                "referencia": "ref",
            },
        })
        with pytest.raises(ValueError, match="severidad_ajustada invalida"):
            _parse_llm_response(data)

    @settings(max_examples=100)
    @given(reason=st.text(min_size=1, max_size=200))
    def test_no_evaluado_verdict_always_has_valid_severity(self, reason):
        """_make_no_evaluado_verdict always returns a valid Severity."""
        verdict = _make_no_evaluado_verdict(reason)
        assert verdict.severidad_ajustada in list(Severity)
        assert verdict.severidad_ajustada == Severity.INFO

    @settings(max_examples=100)
    @given(severity=st.sampled_from(list(Severity)))
    def test_confirmed_finding_severity_is_always_valid_enum(self, severity):
        """ConfirmedFinding.severidad_ajustada built from LLM response is always valid."""
        finding = ConfirmedFinding(
            finding_id="test",
            source="static",
            tipo_vulnerabilidad="test",
            archivo="test.py",
            linea_inicio=1,
            linea_fin=1,
            fragmento_codigo="x = 1",
            severidad_ajustada=severity,
            justificacion="A" * 60,
            recomendacion=Recommendation(
                descripcion="fix",
                codigo_corregido="code",
                referencia="ref",
            ),
            disposition="incluido",
        )
        assert finding.severidad_ajustada in list(Severity)
