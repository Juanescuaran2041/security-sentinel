"""Módulo de formateo de salida CLI — encapsula la lógica de renderizado.

Responsabilidades:
- Detección de soporte ANSI (NO_COLOR, TERM=dumb)
- Renderizado de resultados con Rich (paneles, tablas, colores)
- Renderizado JSON (sin ANSI) para integración con pipelines
- Mapeo severidad → estilo de color
"""

from __future__ import annotations

import json
import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from security_pr_guardian.core.models import (
    AnalysisResult,
    ConfirmedFinding,
    Severity,
    SEVERITY_ORDER,
)


# ---------------------------------------------------------------------------
# Mapeo de severidad a estilo Rich
# ---------------------------------------------------------------------------

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


# ---------------------------------------------------------------------------
# Detección de soporte de colores ANSI
# ---------------------------------------------------------------------------


def should_disable_color() -> bool:
    """Determina si se deben desactivar colores ANSI.

    Retorna True cuando:
    - La variable de entorno NO_COLOR está presente (cualquier valor).
    - La variable de entorno TERM tiene valor 'dumb'.
    """
    if os.environ.get("NO_COLOR") is not None:
        return True
    if os.environ.get("TERM") == "dumb":
        return True
    return False


# ---------------------------------------------------------------------------
# Fábrica de consolas
# ---------------------------------------------------------------------------


def make_console(
    *,
    stderr: bool = False,
    force_no_color: bool = False,
) -> Console:
    """Crea una instancia de Console respetando NO_COLOR / TERM=dumb.

    Args:
        stderr: Si True, la consola escribe en stderr.
        force_no_color: Fuerza la desactivación de colores (ej. modo JSON).
    """
    no_color = force_no_color or should_disable_color()
    return Console(stderr=stderr, no_color=no_color)


# ---------------------------------------------------------------------------
# Renderizado de salida en formato texto
# ---------------------------------------------------------------------------


def render_text_output(result: AnalysisResult, console: Console) -> None:
    """Renderiza la salida en formato texto con colores usando Rich.

    - Sin hallazgos explotables: panel verde con mensaje de éxito.
    - Con hallazgos: panel rojo/amarillo según severidad máxima + tabla.
    - Si diff_truncated=True: advertencia de truncación al final.
    """
    exploitable = [
        f for f in result.confirmed_findings if f.disposition == "incluido"
    ]

    if not exploitable:
        console.print(
            Panel(
                f"[bold green]No se encontraron vulnerabilidades explotables[/bold green]\n"
                f"Candidatos analizados: {result.candidate_count} | "
                f"Descartados: {result.discarded_count} | "
                f"No evaluados: {result.not_evaluated_count}",
                title="Security PR Guardian",
                border_style="green",
            )
        )
        return

    # Determinar estilo según severidad máxima
    max_severity = max(
        (f.severidad_ajustada for f in exploitable),
        key=lambda s: SEVERITY_ORDER[s],
    )
    border_style = (
        "red"
        if SEVERITY_ORDER[max_severity] >= SEVERITY_ORDER[Severity.HIGH]
        else "yellow"
    )

    console.print(
        Panel(
            f"[bold {border_style}]Se encontraron {len(exploitable)} "
            f"vulnerabilidades explotables[/bold {border_style}]",
            title="Security PR Guardian",
            border_style=border_style,
        )
    )

    # Tabla de hallazgos
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severidad", style="bold")
    table.add_column("Tipo")
    table.add_column("Archivo:Línea")
    table.add_column("CVE/CWE")

    for finding in exploitable:
        style = SEVERITY_STYLE.get(finding.severidad_ajustada, "")
        cve_cwe = finding.cve_id or finding.cwe_id or "\u2014"
        table.add_row(
            Text(finding.severidad_ajustada.value.upper(), style=style),
            finding.tipo_vulnerabilidad,
            f"{finding.archivo}:{finding.linea_inicio}",
            cve_cwe,
        )

    console.print(table)

    # Advertencia de truncación
    if result.diff_truncated:
        console.print(
            "[yellow]\u26a0 El diff fue truncado por exceder el l\u00edmite de l\u00edneas. "
            "Algunos hallazgos podr\u00edan no haberse detectado.[/yellow]"
        )


# ---------------------------------------------------------------------------
# Renderizado de salida en formato JSON
# ---------------------------------------------------------------------------


def render_json_output(result: AnalysisResult) -> None:
    """Serializa AnalysisResult completo a JSON en stdout sin ANSI.

    - Usa model_dump con mode='json' para serialización Pydantic nativa.
    - Datetime se serializa como ISO 8601 automáticamente por Pydantic.
    - No emite secuencias ANSI ni formatos Rich.
    - Escribe directamente a sys.stdout.
    """
    json_str = result.model_dump_json(indent=2)
    sys.stdout.write(json_str + "\n")
