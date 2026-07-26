"""Adaptador LLM usando Amazon Bedrock Converse API.

Implementa LLMReasoningPort para evaluar hallazgos candidatos de seguridad
usando un modelo de lenguaje accesible via Bedrock. Incluye reintentos con
backoff exponencial en ThrottlingException y ServiceUnavailableException,
y marcado 'no_evaluado' en fallo definitivo o JSON invalido.
"""

import json
import asyncio
import logging

import boto3
from botocore.exceptions import ClientError

from security_pr_guardian.core.models import (
    CandidateFinding,
    KBFragment,
    LLMVerdict,
    Recommendation,
    Severity,
)
from security_pr_guardian.ports.llm_reasoning import LLMReasoningPort

logger = logging.getLogger(__name__)

# Excepciones de Bedrock que disparan reintentos
_RETRYABLE_ERROR_CODES = frozenset({
    "ThrottlingException",
    "ServiceUnavailableException",
})

# Backoff exponencial: 5s, 10s, 20s
_RETRY_DELAYS = [5, 10, 20]

_SYSTEM_PROMPT = """\
Eres un experto en seguridad de software. Tu tarea es evaluar si un hallazgo \
de seguridad candidato detectado por analisis estatico es realmente explotable \
en el contexto del codigo proporcionado.

Debes responder EXCLUSIVAMENTE con un JSON valido (sin markdown, sin texto \
adicional) con la siguiente estructura exacta:

{
  "es_explotable": true|false,
  "severidad_ajustada": "critical"|"high"|"medium"|"low"|"info",
  "justificacion": "string con al menos 50 caracteres explicando tu razonamiento",
  "recomendacion": {
    "descripcion": "que hacer para remediar",
    "codigo_corregido": "snippet de codigo corregido",
    "referencia": "URL o referencia a documentacion relevante"
  }
}

Criterios de evaluacion:
- Considera el contexto real del codigo: si el input viene de usuario, si hay \
sanitizacion previa, si el framework protege automaticamente.
- Ajusta la severidad segun el impacto real, no solo el patron detectado.
- Si el hallazgo es claramente un falso positivo (ej: uso de MD5 para checksum \
no criptografico, ORM con queries parametrizadas), marca es_explotable=false.
- La justificacion debe ser especifica al codigo analizado, no generica.
"""


def _build_user_prompt(finding: CandidateFinding, kb_context: list[KBFragment]) -> str:
    """Construye el prompt USER con el finding y contexto KB."""
    parts: list[str] = []

    parts.append("## Hallazgo Candidato\n")
    parts.append(f"- **ID:** {finding.finding_id}")
    parts.append(f"- **Tipo:** {finding.tipo_vulnerabilidad}")
    parts.append(f"- **Archivo:** {finding.archivo}")
    parts.append(f"- **Lineas:** {finding.linea_inicio}-{finding.linea_fin}")
    parts.append(f"- **CWE:** {finding.cwe_id or 'N/A'}")
    parts.append(f"- **CVE:** {finding.cve_id or 'N/A'}")
    parts.append(f"- **Severidad inicial:** {finding.severidad_inicial.value}")
    parts.append(f"- **Patron detectado:** {finding.patron_detectado}")
    parts.append(f"\n### Fragmento de codigo\n```\n{finding.fragmento_codigo}\n```")

    if kb_context:
        parts.append("\n## Contexto de la Base de Conocimiento\n")
        for i, fragment in enumerate(kb_context, 1):
            confidence = " (baja confianza)" if fragment.baja_confianza else ""
            parts.append(
                f"### Fragmento {i}: {fragment.titulo}{confidence} "
                f"(score: {fragment.score_relevancia:.2f})\n"
            )
            parts.append(f"Fuente: {fragment.fuente}\n")
            parts.append(f"{fragment.contenido}\n")

    parts.append(
        "\nEvalua si este hallazgo es realmente explotable y responde con el JSON."
    )
    return "\n".join(parts)


def _parse_llm_response(raw_text: str) -> LLMVerdict:
    """Parsea la respuesta JSON del LLM a LLMVerdict.

    Raises:
        ValueError: Si el JSON es invalido o faltan campos requeridos.
    """
    # Limpiar posibles bloques de markdown
    text = raw_text.strip()
    if text.startswith("```"):
        # Remover ```json y ``` finales
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)

    data = json.loads(text)

    #Confirmacion de datos de tipo JSON
    if not isinstance(data, dict):
        raise ValueError(
            f"Se esperaba un objeto JSON, se recibio: {type(data).__name__}"
        )

    # Validar campos requeridos
    required_keys = {"es_explotable", "severidad_ajustada", "justificacion", "recomendacion"}
    missing = required_keys - set(data.keys())
    if missing:
        raise ValueError(f"Campos requeridos faltantes en respuesta LLM: {missing}")

    rec_data = data["recomendacion"]
    rec_required = {"descripcion", "codigo_corregido", "referencia"}
    rec_missing = rec_required - set(rec_data.keys())
    if rec_missing:
        raise ValueError(
            f"Campos requeridos faltantes en recomendacion: {rec_missing}"
        )

    # Validar severidad es un valor valido
    severity_value = data["severidad_ajustada"]
    try:
        severity = Severity(severity_value)
    except ValueError:
        raise ValueError(
            f"severidad_ajustada invalida: '{severity_value}'. "
            f"Valores validos: {[s.value for s in Severity]}"
        )

    # Validar longitud de justificacion
    justificacion = data["justificacion"]
    if len(justificacion) < 50:
        raise ValueError(
            f"justificacion debe tener al menos 50 caracteres, tiene {len(justificacion)}"
        )

    return LLMVerdict(
        es_explotable=bool(data["es_explotable"]),
        severidad_ajustada=severity,
        justificacion=justificacion,
        recomendacion=Recommendation(
            descripcion=rec_data["descripcion"],
            codigo_corregido=rec_data["codigo_corregido"],
            referencia=rec_data["referencia"],
        ),
    )


def _make_no_evaluado_verdict(reason: str) -> LLMVerdict:
    """Genera un veredicto 'no_evaluado' cuando el LLM falla."""
    return LLMVerdict(
        es_explotable=False,
        severidad_ajustada=Severity.INFO,
        justificacion=(
            f"No se pudo evaluar el hallazgo. Razon: {reason}. "
            "Se marca como no evaluado para revision manual posterior. "
            "El hallazgo mantiene su severidad inicial como referencia."
        ),
        recomendacion=Recommendation(
            descripcion="Revision manual requerida - el LLM no pudo evaluar este hallazgo.",
            codigo_corregido="",
            referencia="",
        ),
    )


class BedrockAdapter(LLMReasoningPort):
    """Adaptador que usa Amazon Bedrock Converse API para razonamiento LLM.

    Parameters
    ----------
    region : str
        Region AWS donde esta disponible el modelo (ej: 'us-east-1').
    model_id : str
        ID del modelo en Bedrock (ej: 'anthropic.claude-3-sonnet-20240229-v1:0').
    max_tokens : int
        Maximo de tokens en la respuesta. Default 2048.
    temperature : float
        Temperatura de generacion. Default 0.1 para respuestas deterministas.
    """

    def __init__(self, region: str, model_id: str, max_tokens: int = 2048, temperature: float = 0.1,):
        self._region = region
        self._model_id = model_id
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._client = boto3.client("bedrock-runtime", region_name=region)

    async def evaluate_finding(self, finding: CandidateFinding, kb_context: list[KBFragment]) -> LLMVerdict:
        """Evalua un hallazgo candidato usando Bedrock Converse API.

        Implementa reintentos con backoff exponencial (5s, 10s, 20s) en
        ThrottlingException y ServiceUnavailableException. Retorna veredicto
        'no_evaluado' en fallo definitivo o JSON invalido.
        """
        user_prompt = _build_user_prompt(finding, kb_context)

        messages = [
            {
                "role": "user",
                "content": [{"text": user_prompt}],
            }
        ]

        system = [{"text": _SYSTEM_PROMPT}]

        inference_config = {
            "maxTokens": self._max_tokens,
            "temperature": self._temperature,
        }

        # Intentar con reintentos
        last_error: Exception | None = None
        for attempt, delay in enumerate(
            [0] + _RETRY_DELAYS  # primer intento sin delay
        ):
            if delay > 0:
                logger.warning(
                    "Bedrock retry attempt %d after %ds delay for finding %s",
                    attempt,
                    delay,
                    finding.finding_id,
                )
                await asyncio.sleep(delay)

            try:
                # boto3 es sincrono, ejecutar en thread pool para no bloquear
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._client.converse(
                        modelId=self._model_id,
                        messages=messages,
                        system=system,
                        inferenceConfig=inference_config,
                    ),
                )

                # Extraer texto de la respuesta
                raw_text = self._extract_response_text(response)

                # Parsear respuesta JSON
                return _parse_llm_response(raw_text)

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in _RETRYABLE_ERROR_CODES:
                    last_error = e
                    continue
                # Error no retryable -> no_evaluado inmediato
                logger.error(
                    "Bedrock non-retryable error for finding %s: %s",
                    finding.finding_id,
                    str(e),
                )
                return _make_no_evaluado_verdict(
                    f"Error de Bedrock no recuperable: {error_code}"
                )

            except (json.JSONDecodeError, ValueError, KeyError) as e:
                # JSON invalido o campos faltantes -> no_evaluado sin reintentos
                logger.error(
                    "LLM response parse failure for finding %s: %s",
                    finding.finding_id,
                    str(e),
                )
                return _make_no_evaluado_verdict(
                    f"Respuesta del LLM invalida: {str(e)}"
                )

            except Exception as e:
                # Error inesperado
                logger.error(
                    "Unexpected error evaluating finding %s: %s",
                    finding.finding_id,
                    str(e),
                )
                return _make_no_evaluado_verdict(f"Error inesperado: {str(e)}")

        # Reintentos agotados
        logger.error(
            "Bedrock retries exhausted for finding %s after %d attempts. Last error: %s",
            finding.finding_id,
            len(_RETRY_DELAYS) + 1,
            str(last_error),
        )
        return _make_no_evaluado_verdict(
            f"Reintentos agotados ({len(_RETRY_DELAYS) + 1} intentos). "
            f"Ultimo error: {str(last_error)}"
        )

    def _extract_response_text(self, response: dict) -> str:
        """Extrae el texto de la respuesta de Bedrock Converse API.

        Raises:
            ValueError: Si la estructura de la respuesta es inesperada.
        """
        try:
            output = response["output"]
            message = output["message"]
            content_blocks = message["content"]
            # Concatenar todos los bloques de texto
            texts = [
                block["text"]
                for block in content_blocks
                if "text" in block
            ]
            if not texts:
                raise ValueError("No se encontraron bloques de texto en la respuesta")
            return "\n".join(texts)
        except (KeyError, TypeError) as e:
            raise ValueError(
                f"Estructura de respuesta Bedrock inesperada: {e}"
            ) from e
