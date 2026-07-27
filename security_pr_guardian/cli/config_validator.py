"""Validación de configuración al arranque — variables de entorno obligatorias.

Valida la presencia de todas las variables de entorno requeridas ANTES de
instanciar AppConfig o realizar cualquier llamada a la API.

Produce mensajes estructurados en stderr con el nombre exacto de la variable
ausente y termina con código de salida 2 si falta alguna.
"""

from __future__ import annotations

import os
import sys


def validate_config_at_startup() -> list[str]:
    """Valida las variables de entorno obligatorias al arranque.

    Retorna una lista de nombres de variables de entorno ausentes.
    Si la lista está vacía, todas las variables requeridas están presentes.

    Variables siempre requeridas:
      - GITHUB_TOKEN

    Variables condicionales según LLM_BACKEND:
      - bedrock (default): BEDROCK_REGION, BEDROCK_MODEL_ID
    """
    missing: list[str] = []

    # GITHUB_TOKEN es siempre obligatorio
    if not os.environ.get("GITHUB_TOKEN"):
        missing.append("GITHUB_TOKEN")

    # Bedrock es el único backend LLM
    if not os.environ.get("BEDROCK_REGION"):
        missing.append("BEDROCK_REGION")
    if not os.environ.get("BEDROCK_MODEL_ID"):
        missing.append("BEDROCK_MODEL_ID")

    return missing


def print_missing_config_errors(missing_vars: list[str]) -> None:
    """Imprime mensajes estructurados en stderr para cada variable ausente.

    Formato:
      Error de configuración: variable de entorno obligatoria ausente: VARIABLE_NAME
    """
    for var_name in missing_vars:
        print(
            f"Error de configuración: variable de entorno obligatoria ausente: {var_name}",
            file=sys.stderr,
        )
