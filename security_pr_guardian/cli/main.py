"""CLI principal de Security PR Guardian — click + rich.

Expone dos comandos:
  - security-guardian check --repo <owner/repo> --pr <number> [--output text|json] [--no-comment]
  - security-guardian init

Códigos de salida:
  0 — análisis completo, sin hallazgos explotables
  1 — análisis completo, al menos un hallazgo explotable
  2 — error de configuración, argumentos inválidos o fallo no recuperable
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

import boto3
import click
import httpx
import yaml
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from security_pr_guardian import __version__
from security_pr_guardian.core.models import (
    AllowedPattern,
    AnalysisResult,
    AppConfig,
    ConfirmedFinding,
    Severity,
    TeamProfile,
    SEVERITY_ORDER,
)
from security_pr_guardian.core.logger import StructuredLogger
from security_pr_guardian.core.team_profile import TeamProfileLoader, PROFILE_FILENAME
from security_pr_guardian.core.auto_detect import auto_detect_profile
from security_pr_guardian.cli.output import (
    make_console,
    render_json_output,
    render_text_output,
    should_disable_color,
    SEVERITY_STYLE,
)
from security_pr_guardian.cli.config_validator import (
    print_missing_config_errors,
    validate_config_at_startup,
)


# ---------------------------------------------------------------------------
# Helpers (delegados a cli.output)
# ---------------------------------------------------------------------------

def _should_disable_color() -> bool:
    """Determina si se deben desactivar colores ANSI."""
    return should_disable_color()


def _make_console(force_no_color: bool = False) -> Console:
    """Crea una instancia de Console de Rich respetando NO_COLOR/TERM."""
    return make_console(stderr=True, force_no_color=force_no_color)


def _make_stdout_console(force_no_color: bool = False) -> Console:
    """Consola para salida estándar (stdout)."""
    return make_console(stderr=False, force_no_color=force_no_color)


_SEVERITY_STYLE = SEVERITY_STYLE


def _render_text_output(result: AnalysisResult, console: Console) -> None:
    """Renderiza la salida en formato texto con colores usando Rich."""
    render_text_output(result, console)


def _render_json_output(result: AnalysisResult) -> None:
    """Serializa AnalysisResult a JSON en stdout sin ANSI."""
    render_json_output(result)


def _load_config(console: Console) -> AppConfig | None:
    """Intenta cargar AppConfig. Retorna None si falla."""
    try:
        return AppConfig()  # type: ignore[call-arg]
    except Exception as e:
        error_msg = str(e)
        console.print(f"[bold red]Error de configuración:[/bold red] {error_msg}")
        return None


# ---------------------------------------------------------------------------
# Click CLI
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=__version__, prog_name="security-guardian")
def cli() -> None:
    """Security PR Guardian — Análisis de seguridad inteligente para Pull Requests."""


@cli.command()
@click.option(
    "--repo",
    required=True,
    help="Repositorio en formato owner/repo (ej: octocat/hello-world).",
)
@click.option(
    "--pr",
    required=True,
    type=int,
    help="Número del Pull Request a analizar.",
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Formato de salida: text (default) o json.",
)
@click.option(
    "--no-comment",
    is_flag=True,
    default=False,
    help="Omitir publicación del comentario en el PR (dry-run).",
)
def check(repo: str, pr: int, output_format: str, no_comment: bool) -> None:
    """Analiza un Pull Request en busca de vulnerabilidades de seguridad."""
    is_json = output_format == "json"
    err_console = _make_console(force_no_color=is_json)
    out_console = _make_stdout_console(force_no_color=is_json)

    # Validar variables de entorno obligatorias ANTES de cualquier llamada a API
    missing_vars = validate_config_at_startup()
    if missing_vars:
        print_missing_config_errors(missing_vars)
        raise SystemExit(2)

    # Validar configuración completa (pydantic)
    config = _load_config(err_console)
    if config is None:
        raise SystemExit(2)

    # Validar formato repo
    if "/" not in repo or repo.count("/") != 1:
        err_console.print(
            f"[bold red]Error:[/bold red] El formato del repositorio debe ser owner/repo, "
            f"se recibió: '{repo}'"
        )
        raise SystemExit(2)

    # Generar analysis_id
    analysis_id = str(uuid.uuid4())
    logger = StructuredLogger(analysis_id)

    # Ejecutar análisis
    try:
        result = asyncio.run(_run_analysis(config, repo, pr, no_comment, logger))
    except NotImplementedError as e:
        err_console.print(f"[bold yellow]Advertencia:[/bold yellow] {e}")
        raise SystemExit(2)
    except Exception as e:
        err_console.print(f"[bold red]Error durante el análisis:[/bold red] {e}")
        logger.log(
            componente="CLI",
            evento="analysis_failed",
            error=str(e),
            stage="run_analysis",
        )
        raise SystemExit(2)

    # Determinar código de salida
    exploitable = [
        f for f in result.confirmed_findings if f.disposition == "incluido"
    ]
    exit_code = 1 if exploitable else 0

    # Salida
    if is_json:
        _render_json_output(result)
    else:
        _render_text_output(result, out_console)

    raise SystemExit(exit_code)


@cli.command()
@click.option(
    "--profile",
    "with_profile",
    is_flag=True,
    default=False,
    help="Iniciar cuestionario interactivo para generar .security-guardian.yml.",
)
@click.option(
    "--auto-detect",
    "auto_detect",
    is_flag=True,
    default=False,
    help="Pre-rellenar el cuestionario detectando frameworks y librerías desde los manifiestos del proyecto.",
)
def init(with_profile: bool, auto_detect: bool) -> None:
    """Genera .env.example, valida credenciales, y opcionalmente crea .security-guardian.yml."""
    console = _make_console()
    out_console = _make_stdout_console()

    if with_profile:
        _run_profile_questionnaire(out_console, auto_detect=auto_detect)
        return

    # Comportamiento original: generar .env.example y validar credenciales
    env_example_content = _generate_env_example()
    env_path = Path(".env.example")
    env_path.write_text(env_example_content, encoding="utf-8")
    out_console.print(
        f"[green]✓[/green] Archivo [bold]{env_path}[/bold] generado correctamente."
    )

    out_console.print("\n[bold]Validando credenciales del entorno...[/bold]\n")
    _validate_credentials(out_console)


# ---------------------------------------------------------------------------
# Cuestionario interactivo para .security-guardian.yml
# ---------------------------------------------------------------------------

_SEVERITY_CHOICES = ["critical", "high", "medium", "low", "info"]
_DEFAULT_SEVERITY = "low"


def _run_profile_questionnaire(console: Console, auto_detect: bool = False) -> None:
    """Ejecuta el cuestionario interactivo para generar .security-guardian.yml.

    Parameters
    ----------
    console : Console
        Instancia de Rich Console para mostrar mensajes y prompts.
    auto_detect : bool
        Si True, pre-rellena los valores detectando manifiestos primero.
    """
    cwd = Path.cwd()
    profile_path = cwd / PROFILE_FILENAME

    # --- Paso 1: cargar defaults ---
    # Prioridad: (a) archivo existente > (b) auto-detect > (c) valores vacíos
    existing_profile: TeamProfile | None = None
    if profile_path.exists():
        loader = TeamProfileLoader(cwd=cwd)
        existing_profile = loader.load()
        console.print(
            f"\n[bold yellow]Archivo existente encontrado:[/bold yellow] {PROFILE_FILENAME}"
        )
        console.print("[dim]Los valores actuales se usarán como valores por defecto.[/dim]\n")

    # Defaults iniciales desde el perfil existente (si hay)
    default_frameworks: list[str] = existing_profile.frameworks if existing_profile else []
    default_auth_libs: list[str] = existing_profile.auth_libraries if existing_profile else []
    default_allowed: list[AllowedPattern] = existing_profile.allowed_patterns if existing_profile else []
    default_severity: str = existing_profile.min_severity.value if existing_profile else _DEFAULT_SEVERITY
    default_exceptions: list[str] = existing_profile.custom_exceptions if existing_profile else []

    # Auto-detect: sobreescribe defaults vacíos (si no había archivo)
    if auto_detect:
        try:
            console.print("[bold cyan]🔍 Escaneando archivos del proyecto...[/bold cyan]\n")
            detected = auto_detect_profile(cwd=cwd)
            if not existing_profile:
                # Solo usar auto-detect si no hay un archivo existente que domine
                default_frameworks = detected.get("frameworks") or []
                default_auth_libs = detected.get("auth_libraries") or []
                detected_severity = detected.get("min_severity")
                if detected_severity:
                    default_severity = detected_severity
            else:
                # Con archivo existente: mostrar lo detectado como info adicional
                detected_fw = detected.get("frameworks") or []
                detected_auth = detected.get("auth_libraries") or []
                if detected_fw:
                    console.print(f"[dim]  Frameworks detectados: {', '.join(detected_fw)}[/dim]")
                if detected_auth:
                    console.print(f"[dim]  Auth libs detectadas: {', '.join(detected_auth)}[/dim]")
                console.print()
        except Exception:
            console.print("[yellow]Advertencia: no se pudo ejecutar auto-detect. Continuando sin pre-rellenado.[/yellow]\n")

    # --- Paso 2: cuestionario ---
    console.print(Panel.fit(
        "[bold]Configuración del Perfil de Equipo[/bold]\n"
        "[dim]Responde las preguntas para personalizar el análisis de seguridad.[/dim]",
        border_style="cyan",
    ))
    console.print()

    # Frameworks
    fw_default_str = ", ".join(default_frameworks) if default_frameworks else ""
    fw_prompt = f"Frameworks y lenguajes principales (separados por coma)"
    if fw_default_str:
        fw_prompt += f" [[dim]{fw_default_str}[/dim]]"
    fw_input = Prompt.ask(
        fw_prompt,
        default=fw_default_str,
        console=console,
    )
    frameworks = [f.strip() for f in fw_input.split(",") if f.strip()]

    # Auth libraries
    auth_default_str = ", ".join(default_auth_libs) if default_auth_libs else ""
    auth_prompt = "Librerías de autenticación/hashing (separadas por coma)"
    if auth_default_str:
        auth_prompt += f" [[dim]{auth_default_str}[/dim]]"
    auth_input = Prompt.ask(
        auth_prompt,
        default=auth_default_str,
        console=console,
    )
    auth_libraries = [a.strip() for a in auth_input.split(",") if a.strip()]

    # Allowed patterns
    allowed_patterns = list(default_allowed)  # copia
    if allowed_patterns:
        console.print(f"\n[dim]Patrones permitidos actuales:[/dim]")
        for ap in allowed_patterns:
            console.print(f"  [dim]• {ap.cwe_id}: {ap.razon}[/dim]")

    console.print()
    while True:
        add_pattern = Confirm.ask(
            "¿Añadir un patrón CWE permitido (uso legítimo de algo normalmente flagueado)?",
            default=False,
            console=console,
        )
        if not add_pattern:
            break
        cwe_id = Prompt.ask(
            "  CWE ID (ej: CWE-327)",
            console=console,
        ).strip()
        razon = Prompt.ask(
            "  Razón del uso legítimo",
            console=console,
        ).strip()
        if cwe_id and razon:
            allowed_patterns.append(AllowedPattern(cwe_id=cwe_id, razon=razon))

    # Min severity
    console.print()
    severity_choices_str = "/".join(_SEVERITY_CHOICES)
    sev_input = Prompt.ask(
        f"Severidad mínima a reportar ({severity_choices_str})",
        default=default_severity,
        console=console,
    ).strip().lower()
    if sev_input not in _SEVERITY_CHOICES:
        console.print(f"[yellow]Valor desconocido '{sev_input}', usando '{_DEFAULT_SEVERITY}'.[/yellow]")
        sev_input = _DEFAULT_SEVERITY

    # Custom exceptions
    console.print()
    if default_exceptions:
        console.print("[dim]Excepciones actuales:[/dim]")
        for exc in default_exceptions:
            console.print(f"  [dim]• {exc}[/dim]")

    exc_default_str = "; ".join(default_exceptions) if default_exceptions else ""
    exc_input = Prompt.ask(
        "Excepciones o convenciones del equipo (separadas por punto y coma, o vacío)",
        default=exc_default_str,
        console=console,
    )
    custom_exceptions = [e.strip() for e in exc_input.split(";") if e.strip()]

    # --- Paso 3: confirmación si el archivo ya existe ---
    if profile_path.exists():
        console.print()
        overwrite = Confirm.ask(
            f"[bold yellow]¿Sobrescribir {PROFILE_FILENAME}?[/bold yellow]",
            default=False,
            console=console,
        )
        if not overwrite:
            console.print("[dim]Operación cancelada. El archivo no fue modificado.[/dim]")
            return

    # --- Paso 4: generar el YAML ---
    profile_data = _build_profile_yaml_dict(
        frameworks=frameworks,
        auth_libraries=auth_libraries,
        allowed_patterns=allowed_patterns,
        min_severity=sev_input,
        custom_exceptions=custom_exceptions,
    )

    try:
        yaml_content = yaml.dump(
            profile_data,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )
        profile_path.write_text(yaml_content, encoding="utf-8")
        console.print(
            f"\n[bold green]✓[/bold green] Perfil guardado en [bold]{profile_path}[/bold]"
        )
    except Exception as exc:
        console.print(f"[bold red]Error al escribir {PROFILE_FILENAME}:[/bold red] {exc}")


def _build_profile_yaml_dict(
    frameworks: list[str],
    auth_libraries: list[str],
    allowed_patterns: list[AllowedPattern],
    min_severity: str,
    custom_exceptions: list[str],
) -> dict:
    """Construye el diccionario a serializar como YAML para .security-guardian.yml.

    Parameters
    ----------
    frameworks : list[str]
        Frameworks del proyecto.
    auth_libraries : list[str]
        Librerías de autenticación/hashing.
    allowed_patterns : list[AllowedPattern]
        Patrones CWE permitidos con justificación.
    min_severity : str
        Nivel de severidad mínimo.
    custom_exceptions : list[str]
        Excepciones o convenciones del equipo.

    Returns
    -------
    dict
        Diccionario con la estructura `team_profile: {...}`.
    """
    patterns_list = [
        {"cwe_id": ap.cwe_id, "razon": ap.razon}
        for ap in allowed_patterns
    ]
    return {
        "team_profile": {
            "frameworks": frameworks,
            "auth_libraries": auth_libraries,
            "allowed_patterns": patterns_list,
            "min_severity": min_severity,
            "custom_exceptions": custom_exceptions,
        }
    }


# ---------------------------------------------------------------------------
# Funciones internas de soporte
# ---------------------------------------------------------------------------

async def _run_analysis(
    config: AppConfig,
    repo: str,
    pr_number: int,
    no_comment: bool,
    logger: StructuredLogger,
) -> AnalysisResult:
    """Instancia los adaptadores y ejecuta el pipeline de análisis."""
    from security_pr_guardian.core.agent import SecurityAgent
    from security_pr_guardian.adapters.github.diff_adapter import GitHubDiffAdapter
    from security_pr_guardian.adapters.github.pr_commenter import GitHubPRCommenterAdapter
    from security_pr_guardian.adapters.mcp.static_analyzer_adapter import StaticAnalyzerMCPAdapter
    from security_pr_guardian.adapters.mcp.cve_lookup_adapter import CVELookUpAdapter
    from security_pr_guardian.adapters.kb.chroma_adapter import ChromaKBAdapter
    from security_pr_guardian.adapters.llm.bedrock_adapter import BedrockAdapter

    # Instanciar adaptadores
    diff_adapter = GitHubDiffAdapter(
        token=config.github_token,
        logger=logger,
        max_diff_lines=config.max_diff_lines,
    )

    static_analyzer = StaticAnalyzerMCPAdapter()

    # CVE adapter necesita una sesión MCP — para el MVP usamos None y
    # se resuelve en la implementación del agente cuando no hay manifiestos.
    # Si el agente completo no está listo, esto puede fallar en runtime,
    # pero es la arquitectura correcta.
    cve_adapter = CVELookUpAdapter(
        mcp_session=None,
        max_dependencies=config.max_dependencies,
    )

    kb_adapter = ChromaKBAdapter(logger=logger)

    llm_adapter = BedrockAdapter(
        region=config.bedrock_region or "us-east-1",
        model_id=config.bedrock_model_id or "anthropic.claude-3-sonnet-20240229-v1:0",
    )

    pr_commenter = GitHubPRCommenterAdapter(
        token=config.github_token,
        logger=logger,
    )

    # Instanciar el agente
    agent = SecurityAgent(
        config=config,
        diff_extraction_port=diff_adapter,
        static_analysis_port=static_analyzer,
        cve_lookup_port=cve_adapter,
        kb_retrieval_port=kb_adapter,
        llm_reasoning_port=llm_adapter,
        pr_comment_port=pr_commenter,
        logger=logger,
    )

    # Ejecutar análisis
    return await agent.run(repo, pr_number, dry_run=no_comment)


def _generate_env_example() -> str:
    """Genera el contenido de .env.example."""
    return """\
# ============================================================================
# Security PR Guardian — Variables de entorno
# ============================================================================

# [REQUERIDO] Token de GitHub con permisos de lectura de PRs y escritura de comentarios
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# [REQUERIDO] Región AWS donde está disponible el modelo
BEDROCK_REGION=us-east-1

# [REQUERIDO] ID del modelo en Amazon Bedrock
BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0

# [OPCIONAL] Timeout para consultas a OSV.dev (segundos, default: 10)
# OSV_TIMEOUT_SECONDS=10

# [OPCIONAL] Máximo de líneas del diff a procesar (default: 10000)
# MAX_DIFF_LINES=10000

# [OPCIONAL] Máximo de dependencias a consultar en CVE_Lookup (default: 50)
# MAX_DEPENDENCIES=50
"""


def _validate_credentials(console: Console) -> None:
    """Valida las credenciales configuradas e imprime resultados.

    Para cada credencial:
    1. Verifica que la variable de entorno esté presente.
    2. Si está presente, intenta verificar que funcione realmente:
       - GITHUB_TOKEN: GET /rate_limit para confirmar autenticación.
       - BEDROCK_REGION + BEDROCK_MODEL_ID: STS GetCallerIdentity.
    """
    all_ok = True

    # --- GITHUB_TOKEN ---
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        console.print(
            "  [red]✗[/red] Token de GitHub (GITHUB_TOKEN): [bold red]no configurado[/bold red]"
        )
        all_ok = False
    else:
        # Intentar validar el token contra la API de GitHub
        token_valid = _verify_github_token(github_token)
        if token_valid:
            console.print(
                "  [green]✓[/green] Token de GitHub (GITHUB_TOKEN): configurado y válido"
            )
        else:
            console.print(
                "  [yellow]~[/yellow] Token de GitHub (GITHUB_TOKEN): configurado, "
                "pero no se pudo verificar (puede ser válido)"
            )

    # --- BEDROCK_REGION ---
    bedrock_region = os.environ.get("BEDROCK_REGION")
    if not bedrock_region:
        console.print(
            "  [red]✗[/red] Región de Bedrock (BEDROCK_REGION): [bold red]no configurado[/bold red]"
        )
        all_ok = False
    else:
        console.print(
            "  [green]✓[/green] Región de Bedrock (BEDROCK_REGION): configurado"
        )

    # --- BEDROCK_MODEL_ID ---
    bedrock_model_id = os.environ.get("BEDROCK_MODEL_ID")
    if not bedrock_model_id:
        console.print(
            "  [red]✗[/red] Modelo de Bedrock (BEDROCK_MODEL_ID): [bold red]no configurado[/bold red]"
        )
        all_ok = False
    else:
        console.print(
            "  [green]✓[/green] Modelo de Bedrock (BEDROCK_MODEL_ID): configurado"
        )

    # --- AWS Credentials (STS GetCallerIdentity) ---
    if bedrock_region:
        aws_valid = _verify_aws_credentials(bedrock_region)
        if aws_valid:
            console.print(
                "  [green]✓[/green] Credenciales AWS (STS): válidas"
            )
        else:
            console.print(
                "  [yellow]~[/yellow] Credenciales AWS (STS): no se pudieron verificar"
            )

    console.print()
    if all_ok:
        console.print(
            "[bold green]Todas las credenciales están configuradas correctamente.[/bold green]"
        )
    else:
        console.print(
            "[bold yellow]Algunas credenciales no están configuradas. "
            "Revisa el archivo .env.example para más detalles.[/bold yellow]"
        )


def _verify_github_token(token: str) -> bool:
    """Verifica un token de GitHub haciendo GET /rate_limit.

    Retorna True si el token es válido (respuesta 200 con autenticación).
    Retorna False si la verificación falla (sin crashear).
    """
    try:
        resp = httpx.get(
            "https://api.github.com/rate_limit",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10.0,
        )
        return resp.status_code == 200
    except Exception:
        return False


def _verify_aws_credentials(region: str) -> bool:
    """Verifica credenciales AWS mediante STS GetCallerIdentity.

    Retorna True si las credenciales son válidas.
    Retorna False si la verificación falla (sin crashear).
    """
    try:
        sts = boto3.client("sts", region_name=region)
        sts.get_caller_identity()
        return True
    except Exception:
        return False
