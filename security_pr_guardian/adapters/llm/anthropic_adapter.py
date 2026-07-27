"""Adaptador LLM usando la API directa de Anthropic (Messages API).

Implementa LLMReasoningPort como fallback opcional para desarrollo local
sin consumir cuota AWS. Usa httpx async para las llamadas HTTP.
Incluye reintentos con backoff en rate-limit (429) y errores de conexión,
y marcado 'no_evaluado' en fallo de autenticación (401) o JSON inválido.
"""

import json
import asyncio
import logging

import httpx

from security_pr_guardian.core.models import (
    CandidateFinding,
    KBFragment,
    LLMVerdict,
    TeamProfile,
)
from security_pr_guardian.ports.llm_reasoning import LLMReasoningPort

# Reutilizar helpers del adaptador Bedrock
from security_pr_guardian.adapters.llm.bedrock_adapter import (
    _SYSTEM_PROMPT,
    _build_user_prompt,
    _parse_llm_response,
    _make_no_evaluado_verdict,
)

logger = logging.getLogger(__name__)

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"

# Backoff: 5s, 10s, 20s
_RETRY_DELAYS = [5, 10, 20]


class AnthropicAdapter(LLMReasoningPort):
    """Adaptador que usa la API directa de Anthropic Messages para razonamiento LLM.

    Parameters
    ----------
    api_key : str
        Clave de API de Anthropic (sk-ant-...).
    model : str
        ID del modelo Anthropic. Default: 'claude-3-sonnet-20240229'.
    max_tokens : int
        Máximo de tokens en la respuesta. Default 2048.
    temperature : float
        Temperatura de generación. Default 0.1 para respuestas deterministas.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-sonnet-20240229",
        max_tokens: int = 2048,
        temperature: float = 0.1,
    ):
        self._api_key = api_key
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature

    async def evaluate_finding(
        self, finding: CandidateFinding, kb_context: list[KBFragment],
        team_profile: TeamProfile | None = None
    ) -> LLMVerdict:
        """Evalúa un hallazgo candidato usando Anthropic Messages API.

        Implementa reintentos con backoff (5s, 10s, 20s) en HTTP 429 y
        errores de conexión. Retorna veredicto 'no_evaluado' en fallo
        de autenticación (401) o JSON inválido.
        """
        user_prompt = _build_user_prompt(finding, kb_context)

        payload = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "temperature": self._temperature,
            "system": _SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        }

        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

        last_error: Exception | None = None

        for attempt, delay in enumerate([0] + _RETRY_DELAYS):
            if delay > 0:
                logger.warning(
                    "Anthropic retry attempt %d after %ds delay for finding %s",
                    attempt,
                    delay,
                    finding.finding_id,
                )
                await asyncio.sleep(delay)

            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        _ANTHROPIC_API_URL,
                        json=payload,
                        headers=headers,
                        timeout=60.0,
                    )

                # Errores de autenticación → no_evaluado inmediato
                if response.status_code == 401:
                    logger.error(
                        "Anthropic authentication error for finding %s",
                        finding.finding_id,
                    )
                    return _make_no_evaluado_verdict(
                        "Error de autenticación con la API de Anthropic (401)"
                    )

                # Rate limit → reintentar
                if response.status_code == 429:
                    last_error = httpx.HTTPStatusError(
                        "Rate limited",
                        request=response.request,
                        response=response,
                    )
                    continue

                # Otros errores HTTP no recuperables
                if response.status_code >= 500:
                    last_error = httpx.HTTPStatusError(
                        f"Server error {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                    continue

                response.raise_for_status()

                # Extraer texto de la respuesta
                data = response.json()
                raw_text = self._extract_response_text(data)

                # Parsear respuesta JSON del LLM
                return _parse_llm_response(raw_text)

            except (httpx.ConnectError, httpx.ConnectTimeout) as e:
                last_error = e
                continue

            except (json.JSONDecodeError, ValueError, KeyError) as e:
                logger.error(
                    "LLM response parse failure for finding %s: %s",
                    finding.finding_id,
                    str(e),
                )
                return _make_no_evaluado_verdict(
                    f"Respuesta del LLM inválida: {str(e)}"
                )

            except Exception as e:
                logger.error(
                    "Unexpected error evaluating finding %s: %s",
                    finding.finding_id,
                    str(e),
                )
                return _make_no_evaluado_verdict(f"Error inesperado: {str(e)}")

        # Reintentos agotados
        logger.error(
            "Anthropic retries exhausted for finding %s after %d attempts. Last error: %s",
            finding.finding_id,
            len(_RETRY_DELAYS) + 1,
            str(last_error),
        )
        return _make_no_evaluado_verdict(
            f"Reintentos agotados ({len(_RETRY_DELAYS) + 1} intentos). "
            f"Último error: {str(last_error)}"
        )

    def _extract_response_text(self, data: dict) -> str:
        """Extrae el texto de la respuesta de Anthropic Messages API.

        Raises:
            ValueError: Si la estructura de la respuesta es inesperada.
        """
        try:
            content_blocks = data["content"]
            texts = [
                block["text"]
                for block in content_blocks
                if block.get("type") == "text"
            ]
            if not texts:
                raise ValueError("No se encontraron bloques de texto en la respuesta")
            return "\n".join(texts)
        except (KeyError, TypeError) as e:
            raise ValueError(
                f"Estructura de respuesta Anthropic inesperada: {e}"
            ) from e
