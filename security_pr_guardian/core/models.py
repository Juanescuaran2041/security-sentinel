from enum import Enum
from typing import Literal, Any
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from uuid import uuid4
from datetime import datetime, timezone


class Severity (str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = 'info'

SEVERITY_ORDER = {Severity.CRITICAL: 5, Severity.HIGH: 4,
                  Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}

class CandidateFinding (BaseModel):
    id:str = Field(default_factory=lambda: str(uuid4()))
    source: Literal["static_analysis", "cve"]
    type_vulnerability: str
    file: str
    begin_line: int
    end_line: int
    code_fragment:str = Field(max_length = 10000)
    cwe_id: str | None = None
    cve_id: str | None = None
    severity:Severity

class DependencyChange(BaseModel):
    manifest_file: str             
    package: str
    version: str
    ecosystem: str  

class Recomendation (BaseModel):
    description: str
    reference: str
    code: str

class LLMVeredict (BaseModel):
    exploitable: bool
    adjusted_severity: Severity
    justification: str = Field(min_length = 50)
    recomendation: Recomendation

class ConfirmedFinding (BaseModel):
    id:str = Field(default_factory=lambda: str(uuid4()))
    source: Literal["static_analysis", "cve"]
    type_vulnerability: str
    file: str
    begin_line: int
    end_line: int
    code_fragment:str = Field(max_length = 10000)
    severity:Severity    
    llm_veredict: LLMVeredict
    disposition: Literal["included", "discarded", "not_evaluated"]


class KBFragment(BaseModel):
    titulo: str
    contenido: str
    fuente: str
    score_relevancia: float = Field(ge= 0.0, le=1.0)# 0.0–1.0
    baja_confianza: bool = False

class AnalysisResult(BaseModel):
    analysis_id:str = Field(default_factory=lambda: str(uuid4()))        # UUID v4
    repo: str
    pr_number: int
    candidate_count: int
    confirmed_count: int
    discarded_count: int
    not_evaluated_count: int
    confirmed_findings: list[ConfirmedFinding]
    diff_truncated: bool #El diff fue truncado por exceder el límite
    dependency_limit_exceeded: bool #Limite de dependencias excedido
    comment_id: str | None 
    duration_seconds: float
    model_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
 

class LogEvent (BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    analysis_id: str
    component: str
    event: str
    duration_ms: int | None = None   # solo para operaciones con inicio y fin medibles
    details: dict[str, Any] = Field(default_factory=dict)


class AppConfig (BaseSettings):
    github_token:str
    llm_backend: Literal["bedrock", "anthropic"] = "bedrock"
    bedrock_region: str | None = None
    bedrock_model: str | None = None
    anthropic_api_key: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
    )

    @model_validator(mode="after")
    def validate_credentials_backend(self) -> AppConfig:
        if self.llm_backend == "bedrock":
            if not self.bedrock_model or not self.bedrock_region:
                raise ValueError("Error se debe incluir la region y el modelo de bedrock")
        elif self.llm_backend == "anthropic":
            if not self.anthropic_api_key:
                raise ValueError("Error se debe incluir la API KEY de Anthropic")
        else:
            raise ValueError("Error backend no soportado")
        return self 
    
