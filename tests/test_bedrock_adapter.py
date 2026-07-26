"""Unit tests for BedrockAdapter.

Tests cover:
- Correct prompt construction (SYSTEM + USER with finding and KB context)
- Retry on ThrottlingException (mocked via moto/botocore stubs)
- no_evaluado verdict after exhausted retries (3 ThrottlingExceptions)
- no_evaluado on invalid JSON response
- no_evaluado on missing required fields in response
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from security_pr_guardian.adapters.llm.bedrock_adapter import (
    BedrockAdapter,
    _build_user_prompt,
    _parse_llm_response,
    _make_no_evaluado_verdict,
    _SYSTEM_PROMPT,
)
from security_pr_guardian.core.models import (
    CandidateFinding,
    KBFragment,
    LLMVerdict,
    Recommendation,
    Severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> CandidateFinding:
    """Create a minimal CandidateFinding for testing."""
    defaults = {
        "finding_id": "test-finding-001",
        "source": "static",
        "tipo_vulnerabilidad": "SQL Injection",
        "archivo": "app/views.py",
        "linea_inicio": 42,
        "linea_fin": 44,
        "fragmento_codigo": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        "patron_detectado": "f-string in SQL query",
        "cwe_id": "CWE-89",
        "severidad_inicial": Severity.HIGH,
    }
    defaults.update(overrides)
    return CandidateFinding(**defaults)


def _make_kb_fragment(**overrides) -> KBFragment:
    """Create a minimal KBFragment for testing."""
    defaults = {
        "titulo": "CWE-89: SQL Injection",
        "contenido": "SQL injection occurs when user input is concatenated into queries.",
        "fuente": "knowledge_base/cwes/CWE-89.md",
        "score_relevancia": 0.85,
        "baja_confianza": False,
    }
    defaults.update(overrides)
    return KBFragment(**defaults)


def _valid_llm_response_json() -> str:
    """Return a valid JSON response that the LLM would produce."""
    return json.dumps({
        "es_explotable": True,
        "severidad_ajustada": "high",
        "justificacion": (
            "El codigo concatena directamente user_id en la query SQL sin "
            "sanitizacion ni uso de parametros preparados. Si user_id proviene "
            "de input del usuario, un atacante puede inyectar SQL arbitrario."
        ),
        "recomendacion": {
            "descripcion": "Usar queries parametrizadas en lugar de f-strings.",
            "codigo_corregido": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            "referencia": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        },
    })


def _make_bedrock_response(text: str) -> dict:
    """Build a mock Bedrock Converse API response structure."""
    return {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": text}],
            }
        },
        "stopReason": "end_turn",
        "usage": {"inputTokens": 100, "outputTokens": 200},
    }


def _make_throttling_error() -> ClientError:
    """Create a ThrottlingException ClientError."""
    return ClientError(
        error_response={"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
        operation_name="Converse",
    )


def _make_service_unavailable_error() -> ClientError:
    """Create a ServiceUnavailableException ClientError."""
    return ClientError(
        error_response={"Error": {"Code": "ServiceUnavailableException", "Message": "Service unavailable"}},
        operation_name="Converse",
    )


def _make_access_denied_error() -> ClientError:
    """Create an AccessDeniedException ClientError (non-retryable)."""
    return ClientError(
        error_response={"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
        operation_name="Converse",
    )


# ---------------------------------------------------------------------------
# Tests: Prompt Construction
# ---------------------------------------------------------------------------


class TestPromptConstruction:
    """Tests for _build_user_prompt."""

    def test_prompt_contains_finding_details(self):
        finding = _make_finding()
        prompt = _build_user_prompt(finding, [])

        assert "test-finding-001" in prompt
        assert "SQL Injection" in prompt
        assert "app/views.py" in prompt
        assert "42-44" in prompt
        assert "CWE-89" in prompt
        assert "high" in prompt
        assert "f-string in SQL query" in prompt
        assert 'SELECT * FROM users' in prompt

    def test_prompt_contains_kb_context(self):
        finding = _make_finding()
        kb = [_make_kb_fragment()]
        prompt = _build_user_prompt(finding, kb)

        assert "Contexto de la Base de Conocimiento" in prompt
        assert "CWE-89: SQL Injection" in prompt
        assert "score: 0.85" in prompt
        assert "knowledge_base/cwes/CWE-89.md" in prompt

    def test_prompt_marks_low_confidence_fragments(self):
        finding = _make_finding()
        kb = [_make_kb_fragment(baja_confianza=True, score_relevancia=0.3)]
        prompt = _build_user_prompt(finding, kb)

        assert "(baja confianza)" in prompt

    def test_prompt_without_kb_context(self):
        finding = _make_finding()
        prompt = _build_user_prompt(finding, [])

        assert "Contexto de la Base de Conocimiento" not in prompt

    def test_prompt_handles_none_cwe_and_cve(self):
        finding = _make_finding(cwe_id=None, cve_id=None)
        prompt = _build_user_prompt(finding, [])

        assert "CWE:** N/A" in prompt
        assert "CVE:** N/A" in prompt

    def test_prompt_multiple_kb_fragments(self):
        finding = _make_finding()
        kb = [
            _make_kb_fragment(titulo="Fragment 1", score_relevancia=0.9),
            _make_kb_fragment(titulo="Fragment 2", score_relevancia=0.7),
        ]
        prompt = _build_user_prompt(finding, kb)

        assert "Fragmento 1: Fragment 1" in prompt
        assert "Fragmento 2: Fragment 2" in prompt


# ---------------------------------------------------------------------------
# Tests: Response Parsing
# ---------------------------------------------------------------------------


class TestResponseParsing:
    """Tests for _parse_llm_response."""

    def test_valid_json_parses_correctly(self):
        verdict = _parse_llm_response(_valid_llm_response_json())

        assert verdict.es_explotable is True
        assert verdict.severidad_ajustada == Severity.HIGH
        assert len(verdict.justificacion) >= 50
        assert verdict.recomendacion.descripcion != ""
        assert verdict.recomendacion.codigo_corregido != ""
        assert verdict.recomendacion.referencia != ""

    def test_json_wrapped_in_markdown_code_block(self):
        wrapped = f"```json\n{_valid_llm_response_json()}\n```"
        verdict = _parse_llm_response(wrapped)

        assert verdict.es_explotable is True
        assert verdict.severidad_ajustada == Severity.HIGH

    def test_invalid_json_raises_value_error(self):
        with pytest.raises((json.JSONDecodeError, ValueError)):
            _parse_llm_response("this is not json at all")

    def test_missing_required_field_raises_value_error(self):
        incomplete = json.dumps({
            "es_explotable": True,
            "severidad_ajustada": "high",
            # missing justificacion and recomendacion
        })
        with pytest.raises(ValueError, match="Campos requeridos faltantes"):
            _parse_llm_response(incomplete)

    def test_missing_recomendacion_fields_raises_value_error(self):
        data = json.dumps({
            "es_explotable": True,
            "severidad_ajustada": "high",
            "justificacion": "x" * 60,
            "recomendacion": {"descripcion": "fix it"},  # missing codigo_corregido, referencia
        })
        with pytest.raises(ValueError, match="Campos requeridos faltantes en recomendacion"):
            _parse_llm_response(data)

    def test_invalid_severity_raises_value_error(self):
        data = json.dumps({
            "es_explotable": True,
            "severidad_ajustada": "super_critical",
            "justificacion": "x" * 60,
            "recomendacion": {
                "descripcion": "fix",
                "codigo_corregido": "code",
                "referencia": "ref",
            },
        })
        with pytest.raises(ValueError, match="severidad_ajustada invalida"):
            _parse_llm_response(data)

    def test_short_justificacion_raises_value_error(self):
        data = json.dumps({
            "es_explotable": True,
            "severidad_ajustada": "high",
            "justificacion": "too short",
            "recomendacion": {
                "descripcion": "fix",
                "codigo_corregido": "code",
                "referencia": "ref",
            },
        })
        with pytest.raises(ValueError, match="al menos 50 caracteres"):
            _parse_llm_response(data)


# ---------------------------------------------------------------------------
# Tests: no_evaluado Verdict
# ---------------------------------------------------------------------------


class TestNoEvaluadoVerdict:
    """Tests for _make_no_evaluado_verdict."""

    def test_returns_non_exploitable(self):
        verdict = _make_no_evaluado_verdict("test reason")
        assert verdict.es_explotable is False

    def test_severity_is_info(self):
        verdict = _make_no_evaluado_verdict("test reason")
        assert verdict.severidad_ajustada == Severity.INFO

    def test_justificacion_contains_reason(self):
        verdict = _make_no_evaluado_verdict("network timeout")
        assert "network timeout" in verdict.justificacion

    def test_justificacion_min_length(self):
        verdict = _make_no_evaluado_verdict("x")
        assert len(verdict.justificacion) >= 50


# ---------------------------------------------------------------------------
# Tests: BedrockAdapter.evaluate_finding (integration with mocks)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestBedrockAdapterEvaluateFinding:
    """Tests for BedrockAdapter.evaluate_finding using mocked boto3 client."""

    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.boto3")
    async def test_successful_evaluation(self, mock_boto3):
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.converse.return_value = _make_bedrock_response(
            _valid_llm_response_json()
        )

        adapter = BedrockAdapter(region="us-east-1", model_id="anthropic.claude-3-sonnet-20240229-v1:0")
        finding = _make_finding()

        verdict = await adapter.evaluate_finding(finding, [])

        assert verdict.es_explotable is True
        assert verdict.severidad_ajustada == Severity.HIGH
        mock_client.converse.assert_called_once()

    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.boto3")
    async def test_prompt_structure_sent_to_bedrock(self, mock_boto3):
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.converse.return_value = _make_bedrock_response(
            _valid_llm_response_json()
        )

        adapter = BedrockAdapter(region="us-east-1", model_id="test-model")
        finding = _make_finding()
        kb = [_make_kb_fragment()]

        await adapter.evaluate_finding(finding, kb)

        call_kwargs = mock_client.converse.call_args[1]
        # System prompt is passed
        assert call_kwargs["system"][0]["text"] == _SYSTEM_PROMPT
        # Model ID is correct
        assert call_kwargs["modelId"] == "test-model"
        # Messages contain user role with finding info
        user_content = call_kwargs["messages"][0]["content"][0]["text"]
        assert "SQL Injection" in user_content
        assert "CWE-89" in user_content

    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.asyncio.sleep", new_callable=AsyncMock)
    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.boto3")
    async def test_retry_on_throttling_then_success(self, mock_boto3, mock_sleep):
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        # First call throttled, second succeeds
        mock_client.converse.side_effect = [
            _make_throttling_error(),
            _make_bedrock_response(_valid_llm_response_json()),
        ]

        adapter = BedrockAdapter(region="us-east-1", model_id="test-model")
        finding = _make_finding()

        verdict = await adapter.evaluate_finding(finding, [])

        assert verdict.es_explotable is True
        assert mock_client.converse.call_count == 2
        # Sleep was called for the retry delay
        mock_sleep.assert_called_once_with(5)

    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.asyncio.sleep", new_callable=AsyncMock)
    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.boto3")
    async def test_no_evaluado_after_exhausted_retries(self, mock_boto3, mock_sleep):
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        # All 4 attempts (1 initial + 3 retries) fail with throttling
        mock_client.converse.side_effect = [
            _make_throttling_error(),
            _make_throttling_error(),
            _make_throttling_error(),
            _make_throttling_error(),
        ]

        adapter = BedrockAdapter(region="us-east-1", model_id="test-model")
        finding = _make_finding()

        verdict = await adapter.evaluate_finding(finding, [])

        assert verdict.es_explotable is False
        assert verdict.severidad_ajustada == Severity.INFO
        assert "Reintentos agotados" in verdict.justificacion
        assert mock_client.converse.call_count == 4

    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.asyncio.sleep", new_callable=AsyncMock)
    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.boto3")
    async def test_retry_on_service_unavailable(self, mock_boto3, mock_sleep):
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.converse.side_effect = [
            _make_service_unavailable_error(),
            _make_bedrock_response(_valid_llm_response_json()),
        ]

        adapter = BedrockAdapter(region="us-east-1", model_id="test-model")
        finding = _make_finding()

        verdict = await adapter.evaluate_finding(finding, [])

        assert verdict.es_explotable is True
        assert mock_client.converse.call_count == 2

    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.boto3")
    async def test_no_evaluado_on_non_retryable_error(self, mock_boto3):
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.converse.side_effect = _make_access_denied_error()

        adapter = BedrockAdapter(region="us-east-1", model_id="test-model")
        finding = _make_finding()

        verdict = await adapter.evaluate_finding(finding, [])

        assert verdict.es_explotable is False
        assert verdict.severidad_ajustada == Severity.INFO
        assert "AccessDeniedException" in verdict.justificacion
        # No retries for non-retryable errors
        assert mock_client.converse.call_count == 1

    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.boto3")
    async def test_no_evaluado_on_invalid_json_response(self, mock_boto3):
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.converse.return_value = _make_bedrock_response(
            "This is not JSON, just some random text from the LLM."
        )

        adapter = BedrockAdapter(region="us-east-1", model_id="test-model")
        finding = _make_finding()

        verdict = await adapter.evaluate_finding(finding, [])

        assert verdict.es_explotable is False
        assert verdict.severidad_ajustada == Severity.INFO
        assert "invalida" in verdict.justificacion

    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.boto3")
    async def test_no_evaluado_on_missing_fields_in_response(self, mock_boto3):
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        # Valid JSON but missing required fields
        incomplete_response = json.dumps({"es_explotable": True})
        mock_client.converse.return_value = _make_bedrock_response(incomplete_response)

        adapter = BedrockAdapter(region="us-east-1", model_id="test-model")
        finding = _make_finding()

        verdict = await adapter.evaluate_finding(finding, [])

        assert verdict.es_explotable is False
        assert verdict.severidad_ajustada == Severity.INFO
        assert "invalida" in verdict.justificacion

    @patch("security_pr_guardian.adapters.llm.bedrock_adapter.boto3")
    async def test_inference_config_uses_constructor_params(self, mock_boto3):
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.converse.return_value = _make_bedrock_response(
            _valid_llm_response_json()
        )

        adapter = BedrockAdapter(
            region="eu-west-1",
            model_id="custom-model",
            max_tokens=4096,
            temperature=0.5,
        )
        await adapter.evaluate_finding(_make_finding(), [])

        call_kwargs = mock_client.converse.call_args[1]
        assert call_kwargs["inferenceConfig"]["maxTokens"] == 4096
        assert call_kwargs["inferenceConfig"]["temperature"] == 0.5
