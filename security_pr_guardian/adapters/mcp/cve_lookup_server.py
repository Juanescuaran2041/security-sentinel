"""Servidor FastMCP CVE_Lookup — consulta OSV.dev por vulnerabilidades conocidas.

Expone la tool `lookup_cve(package, version, ecosystem)` que llama a
POST https://api.osv.dev/v1/querybatch con reintentos y manejo de errores.

Requisitos cubiertos:
  - Req 4.1: CVE_Lookup expuesto como MCP tool.
  - Req 4.2: version vacía → ErrorFinding tipo error_input (sin reintento).
  - Req 4.3: retorna CVEFinding por cada vulnerabilidad encontrada.
  - Req 4.4: sin vulnerabilidades → lista vacía [].
  - Req 4.5: 2 reintentos adicionales (3 intentos total), espera fija 3s,
             luego ErrorFinding tipo error_lookup.
"""

import asyncio
import logging

import httpx
from mcp.server.fastmcp import FastMCP

from security_pr_guardian.core.models import CVEFinding, ErrorFinding

logger = logging.getLogger(__name__)

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
HTTP_TIMEOUT_SECONDS = 10.0
MAX_ATTEMPTS = 3          # 1 intento inicial + 2 reintentos
RETRY_WAIT_SECONDS = 3

mcp = FastMCP("cve-lookup")


def _map_severity(vuln: dict) -> str:
    """Extrae y normaliza el nivel de severidad desde un objeto de vulnerabilidad OSV.

    OSV puede reportar severidad en distintos lugares:
      1. severity[].score  (CVSS v3 score string, ej. "CVSS:3.1/.../7.5")
      2. database_specific.severity  (string libre, ej. "HIGH")
      3. affected[].severity (otro lugar posible)

    Retorna uno de: "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE".
    """
    # Mapa de etiquetas textuales a nuestro enum
    _label_map = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "moderate": "HIGH",   # npm usa "moderate" ≈ HIGH
        "medium": "MEDIUM",
        "low": "LOW",
        "none": "NONE",
    }

    # 1. Intentar desde severity[].score (formato CVSS string)
    for entry in vuln.get("severity", []):
        score_str: str = entry.get("score", "")
        # CVSS v3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" — base score en AV
        # OSV también puede tener severity como {"type": "CVSS_V3", "score": "7.5"}
        # Intentar como número flotante primero
        try:
            numeric = float(score_str)
            if numeric >= 9.0:
                return "CRITICAL"
            elif numeric >= 7.0:
                return "HIGH"
            elif numeric >= 4.0:
                return "MEDIUM"
            elif numeric > 0.0:
                return "LOW"
            else:
                return "NONE"
        except ValueError:
            pass
        # Intentar como etiqueta de texto
        label = _label_map.get(score_str.lower().split("/")[0], None)
        if label:
            return label

    # 2. Intentar desde database_specific.severity
    db_specific = vuln.get("database_specific", {})
    db_sev = db_specific.get("severity", "")
    if db_sev:
        label = _label_map.get(db_sev.lower(), None)
        if label:
            return label

    # 3. Fallback
    return "NONE"


def _extract_references(vuln: dict) -> list[str]:
    """Extrae URLs de referencias desde un objeto de vulnerabilidad OSV."""
    refs: list[str] = []
    for ref in vuln.get("references", []):
        url = ref.get("url", "")
        if url:
            refs.append(url)
    return refs


def _parse_vulns(vulns: list[dict], package: str, version: str, ecosystem: str) -> list[CVEFinding]:
    """Convierte la lista de vulns OSV en objetos CVEFinding."""
    findings: list[CVEFinding] = []
    for vuln in vulns:
        cve_id = vuln.get("id", "UNKNOWN")
        # Preferir aliases CVE-XXXX-XXXX si está disponible
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        summary = vuln.get("summary") or vuln.get("details") or ""
        # Truncar descripción larga
        descripcion = summary[:500] if len(summary) > 500 else summary

        findings.append(
            CVEFinding(
                cve_id=cve_id,
                paquete=package,
                version=version,
                ecosistema=ecosystem,
                severidad=_map_severity(vuln),
                descripcion=descripcion,
                referencias=_extract_references(vuln),
            )
        )
    return findings


@mcp.tool()
async def lookup_cve(package: str, version: str, ecosystem: str) -> list[CVEFinding] | ErrorFinding:
    """Consulta OSV.dev por vulnerabilidades conocidas para un paquete.

    Args:
        package:   Nombre del paquete (ej. "requests", "lodash").
        version:   Versión exacta a consultar (ej. "2.28.0").
        ecosystem: Ecosistema del paquete (ej. "PyPI", "npm", "crates.io").

    Returns:
        Lista de CVEFinding si hay vulnerabilidades, lista vacía si no hay,
        o ErrorFinding en caso de entrada inválida o fallo de red definitivo.
    """
    # Req 4.2: versión vacía → error_input inmediato, sin reintento
    if not version or not version.strip():
        return ErrorFinding(
            tipo="error_input",
            paquete=package,
            version=version,
            ecosistema=ecosystem,
            error_descripcion=(
                f"La versión no puede estar vacía para el paquete '{package}' "
                f"en el ecosistema '{ecosystem}'."
            ),
        )

    payload = {
        "queries": [
            {
                "version": version,
                "package": {
                    "name": package,
                    "ecosystem": ecosystem,
                },
            }
        ]
    }

    last_error: str = "Error desconocido"

    # Req 4.5: 3 intentos en total (1 inicial + 2 reintentos), espera fija de 3s
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = await client.post(OSV_QUERYBATCH_URL, json=payload)
                response.raise_for_status()

                data = response.json()
                # Estructura: {"results": [{"vulns": [...]}]}
                results = data.get("results", [])
                vulns: list[dict] = []
                if results:
                    vulns = results[0].get("vulns", []) or []

                # Req 4.4: sin vulnerabilidades → lista vacía
                if not vulns:
                    return []

                # Req 4.3: construir CVEFinding por cada vulnerabilidad
                return _parse_vulns(vulns, package, version, ecosystem)

            except httpx.HTTPStatusError as exc:
                last_error = (
                    f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
                )
                logger.warning(
                    "CVE lookup HTTP error (intento %d/%d): %s",
                    attempt,
                    MAX_ATTEMPTS,
                    last_error,
                )
            except (httpx.TimeoutException, httpx.RequestError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "CVE lookup red/timeout error (intento %d/%d): %s",
                    attempt,
                    MAX_ATTEMPTS,
                    last_error,
                )

            # No esperar después del último intento fallido
            if attempt < MAX_ATTEMPTS:
                await asyncio.sleep(RETRY_WAIT_SECONDS)

    # Req 4.5: reintentos agotados → error_lookup
    return ErrorFinding(
        tipo="error_lookup",
        paquete=package,
        version=version,
        ecosistema=ecosystem,
        error_descripcion=(
            f"Fallo definitivo al consultar OSV.dev tras {MAX_ATTEMPTS} intentos. "
            f"Último error: {last_error}"
        ),
    )


if __name__ == "__main__":
    mcp.run()
