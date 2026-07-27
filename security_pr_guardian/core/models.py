"""Modelos de dominio para Security PR Guardian.

Todos los modelos siguen la especificacion del documento de diseno.
"""

from enum import Enum
from typing import Any, Literal
from uuid import uuid4
from datetime import datetime, timezone

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Severity(str, Enum):
    """Niveles de severidad para hallazgos de seguridad."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class CandidateFinding(BaseModel):
    """Hallazgo candidato detectado por SAST o escaneo CVE."""

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    source: Literal["static", "cve"]
    tipo_vulnerabilidad: str
    archivo: str
    linea_inicio: int
    linea_fin: int
    fragmento_codigo: str = Field(max_length=500)
    patron_detectado: str
    cwe_id: str | None = None
    cve_id: str | None = None
    paquete: str | None = None  # solo para findings CVE
    version: str | None = None
    ecosistema: str | None = None
    severidad_inicial: Severity


class Recommendation(BaseModel):
    """Recomendacion de remediacion generada por el LLM."""

    descripcion: str
    codigo_corregido: str
    referencia: str


class LLMVerdict(BaseModel):
    """Veredicto del LLM sobre un hallazgo candidato."""

    es_explotable: bool
    severidad_ajustada: Severity
    justificacion: str = Field(min_length=50)
    recomendacion: Recommendation


class ConfirmedFinding(BaseModel):
    """Hallazgo confirmado tras evaluacion LLM."""

    finding_id: str
    source: Literal["static", "cve"]
    tipo_vulnerabilidad: str
    archivo: str
    linea_inicio: int
    linea_fin: int
    fragmento_codigo: str
    cwe_id: str | None = None
    cve_id: str | None = None
    severidad_ajustada: Severity
    justificacion: str
    recomendacion: Recommendation
    disposition: Literal["incluido", "descartado", "no_evaluado"]


class KBFragment(BaseModel):
    """Fragmento de la base de conocimiento recuperado por similitud."""

    titulo: str
    contenido: str
    fuente: str
    score_relevancia: float = Field(ge=0.0, le=1.0)
    baja_confianza: bool = False


class AnalysisResult(BaseModel):
    """Resultado final de un analisis de PR."""

    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    repo: str
    pr_number: int
    candidate_count: int
    confirmed_count: int
    discarded_count: int
    not_evaluated_count: int
    confirmed_findings: list[ConfirmedFinding]
    diff_truncated: bool
    dependency_limit_exceeded: bool
    comment_id: str | None = None
    duration_seconds: float
    model_id: str
    guardian_version: str
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AppConfig(BaseSettings):
    """Configuracion de la aplicacion con validacion de credenciales."""

    github_token: str
    llm_backend: Literal["bedrock", "anthropic"] = "bedrock"
    bedrock_region: str | None = None
    bedrock_model_id: str | None = None
    anthropic_api_key: str | None = None
    osv_timeout_seconds: int = Field(default=10, ge=1, le=300)
    max_diff_lines: int = Field(default=10000, ge=1, le=10000)
    max_dependencies: int = Field(default=50, ge=1, le=1000)

    model_config = SettingsConfigDict(
        env_file=".env",
        yaml_file="config.yaml",
        env_prefix="",
        case_sensitive=False,
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_credentials_backend(self) -> "AppConfig":
        if self.llm_backend == "bedrock":
            if not self.bedrock_region or not self.bedrock_model_id:
                raise ValueError(
                    "Error: se requieren bedrock_region y bedrock_model_id "
                    'cuando llm_backend = "bedrock"'
                )
        elif self.llm_backend == "anthropic":
            if not self.anthropic_api_key:
                raise ValueError(
                    "Error: se requiere anthropic_api_key "
                    'cuando llm_backend = "anthropic"'
                )
        return self


class DependencyChange(BaseModel):
    """Cambio de dependencia detectado en el diff."""

    manifest_file: str
    package: str
    version: str
    ecosystem: str


class LogEvent(BaseModel):
    """Evento de log estructurado."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    analysis_id: str
    componente: str
    evento: str
    duracion_ms: int | None = None
    detalle: dict[str, Any] = Field(default_factory=dict)


class StaticAnalysisResult(BaseModel):
    """Resultado del analisis estatico SAST."""

    findings: list[CandidateFinding] = Field(default_factory=list)
    errores_parciales: list[dict[str, str]] = Field(default_factory=list)


class CVEFinding(BaseModel):
    """Hallazgo de vulnerabilidad CVE retornado por el servidor MCP CVE_Lookup."""

    cve_id: str
    paquete: str
    version: str
    ecosistema: str
    severidad: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    descripcion: str
    referencias: list[str]


class ErrorFinding(BaseModel):
    """Error estructurado retornado por el servidor MCP CVE_Lookup en casos de fallo."""

    tipo: Literal["error_input", "error_lookup", "limit_exceeded"]
    paquete: str
    version: str
    ecosistema: str
    error_descripcion: str


class AllowedPattern(BaseModel):
    """Patron CWE permitido con justificacion de uso legitimo."""

    cwe_id: str   # formato "CWE-<número>"
    razon: str    # descripción del uso legítimo


class TeamProfile(BaseModel):
    """Perfil del equipo para personalizar el analisis de seguridad."""

    frameworks: list[str] = []                   # ej. ["django", "react", "fastapi"]
    auth_libraries: list[str] = []               # ej. ["bcrypt", "django-allauth"]
    allowed_patterns: list[AllowedPattern] = []  # patrones CWE permitidos con razón
    min_severity: Severity = Severity.LOW        # severidad mínima a reportar
    custom_exceptions: list[str] = []            # texto libre de convenciones del equipo
