"""SecurityAgent — Orquestador central del pipeline de análisis de seguridad.

Coordina el flujo completo: diff → SAST → CVE → KB → LLM → PR comment.
Genera un analysis_id UUID v4 único por ejecución y lo propaga a todos
los componentes vía el StructuredLogger. Aplica el tope de 20 hallazgos
ordenados por severidad descendente antes de invocar el LLM.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from security_pr_guardian.core.diff_parser import DiffParser
from security_pr_guardian.core.logger import StructuredLogger
from security_pr_guardian.core.team_profile import TeamProfileLoader

from security_pr_guardian.core.models import (
    AnalysisResult,
    AppConfig,
    CandidateFinding,
    ConfirmedFinding,
    CVEFinding,
    Recommendation,
    Severity,
    SEVERITY_ORDER,
    StaticAnalysisResult,
    TeamProfile,
)
from security_pr_guardian.ports.cve_lookup import CVELookupPort
from security_pr_guardian.ports.diff_extraction import DiffExtractionPort
from security_pr_guardian.ports.kb_retrieval import KBRetrievalPort
from security_pr_guardian.ports.llm_reasoning import LLMReasoningPort
from security_pr_guardian.ports.pr_comment import PRCommentPort
from security_pr_guardian.ports.static_analysis import StaticAnalysisPort

MAX_FINDINGS_LLM = 60


class SecurityAgent:
    """Orquestador central del pipeline de análisis de seguridad.

    Responsabilidades:
    - Genera analysis_id (UUID v4) y lo propaga a todos los componentes.
    - Orquesta el pipeline: diff → SAST → CVE → KB → LLM → PR comment.
    - Ordena candidatos por severidad descendente y aplica tope de 20.
    - Maneja el flag dry-run (--no-comment).
    - Emite eventos de log estructurado en cada etapa.
    """

    def __init__(
        self,
        config: AppConfig,
        diff_extraction_port: DiffExtractionPort,
        static_analysis_port: StaticAnalysisPort,
        cve_lookup_port: CVELookupPort,
        kb_retrieval_port: KBRetrievalPort,
        llm_reasoning_port: LLMReasoningPort,
        pr_comment_port: PRCommentPort,
        logger: StructuredLogger | None = None,
        team_profile: TeamProfile | None = None,
    ):
        self.config = config
        self.diff_extraction_port = diff_extraction_port
        self.static_analysis_port = static_analysis_port
        self.cve_lookup_port = cve_lookup_port
        self.kb_retrieval_port = kb_retrieval_port
        self.llm_reasoning_port = llm_reasoning_port
        self.pr_comment_port = pr_comment_port
        self.team_profile = team_profile
        # Logger will be replaced per run with the correct analysis_id
        self._provided_logger = logger

    async def run(
        self, repo: str, pr_number: int, dry_run: bool = False
    ) -> AnalysisResult:
        """Ejecuta el pipeline completo de análisis de seguridad.

        Args:
            repo: Identificador del repositorio (formato 'owner/repo').
            pr_number: Número del Pull Request.
            dry_run: Si True, omite la publicación del comentario en el PR.

        Returns:
            AnalysisResult con todos los hallazgos y métricas.
        """
        # Generate unique analysis_id for this run
        analysis_id = str(uuid.uuid4())
        start_time = time.monotonic()

        # Create or use logger with the correct analysis_id
        if self._provided_logger is not None:
            # Use provided logger's output but create one with correct analysis_id
            logger = StructuredLogger(analysis_id, output=self._provided_logger._output)
        else:
            logger = StructuredLogger(analysis_id)

        # --- Stage: Analysis Started ---
        logger.log(
            componente="Security_Agent",
            evento="analysis_started",
            repo=repo,
            pr_number=pr_number,
            dry_run=dry_run,
        )

        # --- Stage: Diff Fetch ---
        diff_start = time.monotonic()
        diff_raw = await self.diff_extraction_port.get_diff(repo, pr_number)
        diff_elapsed_ms = int((time.monotonic() - diff_start) * 1000)

        logger.log(
            componente="Security_Agent",
            evento="diff_fetch_complete",
            duracion_ms=diff_elapsed_ms,
            chars=len(diff_raw),
        )

        # --- Stage: Parse Diff ---
        parser = DiffParser(max_diff_lines=self.config.max_diff_lines)
        parsed = parser.parse(diff_raw)

        # Truncate diff for SAST if needed
        if parsed.diff_truncated:
            diff_for_sast, _ = parser.truncate_diff(diff_raw)
            logger.log(
                componente="Diff_Parser",
                evento="diff_truncated",
                original_lines=parsed.total_added_lines,
                max_lines=self.config.max_diff_lines,
            )
        else:
            diff_for_sast = diff_raw

        # --- Stage: Static Analysis (SAST) ---
        sast_start = time.monotonic()
        sast_result: StaticAnalysisResult = (
            await self.static_analysis_port.analyze_diff(diff_for_sast)
        )
        sast_elapsed_ms = int((time.monotonic() - sast_start) * 1000)

        logger.log(
            componente="Static_Analyzer",
            evento="static_analysis_complete",
            duracion_ms=sast_elapsed_ms,
            findings_count=len(sast_result.findings),
            errores_parciales=len(sast_result.errores_parciales),
        )

        # --- Stage: CVE Lookup (only if manifests present) ---
        cve_findings: list[Any] = []
        has_manifests = len(parsed.manifest_files) > 0

        if has_manifests:
            cve_start = time.monotonic()
            cve_findings = await self.cve_lookup_port.lookup_vulnerabilities(
                parsed.dependency_changes
            )
            cve_elapsed_ms = int((time.monotonic() - cve_start) * 1000)

            logger.log(
                componente="CVE_Lookup",
                evento="cve_lookup_complete",
                duracion_ms=cve_elapsed_ms,
                findings_count=len(
                    [f for f in cve_findings if isinstance(f, CVEFinding)]
                ),
            )
        # If no manifests, CVE lookup is skipped entirely

        # --- Convert CVE findings to CandidateFinding ---
        cve_candidates = [
            self._cve_to_candidate(f)
            for f in cve_findings
            if isinstance(f, CVEFinding)
        ]

        # Detect dependency_limit_exceeded
        dependency_limit_exceeded = any(
            hasattr(f, "tipo") and f.tipo == "limit_exceeded" for f in cve_findings
        )

        if dependency_limit_exceeded:
            logger.log(
                componente="Security_Agent",
                evento="limit_exceeded",
                source="dependencies",
            )

        # --- Merge and sort candidates by severity descending ---
        all_candidates = sast_result.findings + cve_candidates
        candidates_sorted = sorted(
            all_candidates,
            key=lambda c: SEVERITY_ORDER[c.severidad_inicial],
            reverse=True,
        )

        # Cap at MAX_FINDINGS_LLM
        candidates_for_llm = candidates_sorted[:MAX_FINDINGS_LLM]

        # --- Stage: KB Retrieval + LLM Evaluation per candidate ---
        confirmed_findings: list[ConfirmedFinding] = []

        for candidate in candidates_for_llm:
            # KB retrieval
            kb_start = time.monotonic()
            kb_fragments = await self.kb_retrieval_port.retrieve(candidate)
            kb_elapsed_ms = int((time.monotonic() - kb_start) * 1000)

            logger.log(
                componente="KB_Retriever",
                evento="kb_retrieval_complete",
                duracion_ms=kb_elapsed_ms,
                finding_id=candidate.finding_id,
                fragments_count=len(kb_fragments),
            )

            # LLM evaluation
            try:
                llm_start = time.monotonic()
                verdict = await self.llm_reasoning_port.evaluate_finding(
                    candidate, kb_fragments, self.team_profile
                )
                llm_elapsed_ms = int((time.monotonic() - llm_start) * 1000)

                disposition = "incluido" if verdict.es_explotable else "descartado"
                severidad = verdict.severidad_ajustada
                justificacion = verdict.justificacion
                recomendacion = verdict.recomendacion

                logger.log(
                    componente="Security_Agent",
                    evento="llm_call_complete",
                    duracion_ms=llm_elapsed_ms,
                    finding_id=candidate.finding_id,
                )

            except Exception as e:
                # LLM failure → no_evaluado
                disposition = "no_evaluado"
                severidad = candidate.severidad_inicial
                justificacion = f"No evaluado por fallo del LLM: {e}"
                recomendacion = Recommendation(
                    descripcion="Revisión manual recomendada.",
                    codigo_corregido="",
                    referencia=candidate.cwe_id or candidate.cve_id or "",
                )

                logger.log(
                    componente="Security_Agent",
                    evento="llm_parse_failure",
                    finding_id=candidate.finding_id,
                    error=str(e),
                )

            # Log finding evaluation result
            logger.log(
                componente="Security_Agent",
                evento="finding_evaluated",
                finding_id=candidate.finding_id,
                es_explotable=(disposition == "incluido"),
                severidad_ajustada=severidad.value,
                justificacion=justificacion[:200],
                disposition=disposition,
            )

            confirmed_findings.append(
                ConfirmedFinding(
                    finding_id=candidate.finding_id,
                    source=candidate.source,
                    tipo_vulnerabilidad=candidate.tipo_vulnerabilidad,
                    archivo=candidate.archivo,
                    linea_inicio=candidate.linea_inicio,
                    linea_fin=candidate.linea_fin,
                    fragmento_codigo=candidate.fragmento_codigo,
                    cwe_id=candidate.cwe_id,
                    cve_id=candidate.cve_id,
                    severidad_ajustada=severidad,
                    justificacion=justificacion,
                    recomendacion=recomendacion,
                    disposition=disposition,
                )
            )

        # --- Sort confirmed findings by severity descending ---
        confirmed_findings.sort(
            key=lambda f: SEVERITY_ORDER[f.severidad_ajustada], reverse=True
        )

        # --- Compute counts ---
        duration_seconds = time.monotonic() - start_time
        confirmed = [f for f in confirmed_findings if f.disposition == "incluido"]
        discarded = [f for f in confirmed_findings if f.disposition == "descartado"]
        not_evaluated = [
            f for f in confirmed_findings if f.disposition == "no_evaluado"
        ]

        # --- Build result ---
        result = AnalysisResult(
            analysis_id=analysis_id,
            repo=repo,
            pr_number=pr_number,
            candidate_count=len(all_candidates),
            confirmed_count=len(confirmed),
            discarded_count=len(discarded),
            not_evaluated_count=len(not_evaluated),
            confirmed_findings=confirmed_findings,
            diff_truncated=parsed.diff_truncated,
            dependency_limit_exceeded=dependency_limit_exceeded,
            duration_seconds=duration_seconds,
            model_id=self.config.bedrock_model_id or "anthropic",
            guardian_version="0.1.0",
        )

        # --- Stage: PR Comment (unless dry_run) ---
        if not dry_run:
            comment_start = time.monotonic()
            comment_id = await self.pr_comment_port.post_or_update_comment(
                repo, pr_number, result
            )
            comment_elapsed_ms = int((time.monotonic() - comment_start) * 1000)
            result = result.model_copy(update={"comment_id": comment_id})

            logger.log(
                componente="PR_Commenter",
                evento="comment_publish_complete",
                duracion_ms=comment_elapsed_ms,
                comment_id=comment_id,
            )

        # --- Stage: Analysis Complete ---
        total_duration_ms = int((time.monotonic() - start_time) * 1000)
        logger.log(
            componente="Security_Agent",
            evento="analysis_complete",
            duracion_ms=total_duration_ms,
            candidate_count=len(all_candidates),
            confirmed_count=len(confirmed),
            discarded_count=len(discarded),
            not_evaluated_count=len(not_evaluated),
        )

        return result

    def _cve_to_candidate(self, cve: CVEFinding) -> CandidateFinding:
        """Convierte un CVEFinding a CandidateFinding."""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "NONE": Severity.INFO,
        }

        return CandidateFinding(
            source="cve",
            tipo_vulnerabilidad=cve.descripcion,
            archivo=f"{cve.ecosistema}/{cve.paquete}",
            linea_inicio=0,
            linea_fin=0,
            fragmento_codigo=f"{cve.paquete} == {cve.version}",
            patron_detectado=cve.cve_id,
            cve_id=cve.cve_id,
            paquete=cve.paquete,
            version=cve.version,
            ecosistema=cve.ecosistema,
            severidad_inicial=severity_map.get(cve.severidad, Severity.MEDIUM),
        )
