from __future__ import annotations

import uuid
import time
import asyncio
from datetime import datetime, timezone

from security_pr_guardian.core.logger import StructuredLogger
from security_pr_guardian.core.team_profile import TeamProfileLoader

from security_pr_guardian.core.models import (
    AnalysisResult,
    AppConfig,
    CandidateFinding,
    ConfirmedFinding,
    CVEFinding,
    DependencyChange,
    Recommendation,
    Severity,
    SEVERITY_ORDER,
    TeamProfile,
)

from security_pr_guardian.core.diff_parser import DiffParser

from security_pr_guardian.ports.diff_extraction import DiffExtractionPort
from security_pr_guardian.ports.static_analysis import StaticAnalysisPort
from security_pr_guardian.ports.cve_lookup import CVELookupPort
from security_pr_guardian.ports.kb_retrieval import KBRetrievalPort
from security_pr_guardian.ports.llm_reasoning import LLMReasoningPort
from security_pr_guardian.ports.pr_comment import PRCommentPort

MAX_FINDINGS_LLM = 20

class SecurityAgent:

    def __init__(self, 
    
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

        self.logger = logger

        analysis_id = str(uuid.uuid4())

        self._logger = logger or StructuredLogger(analysis_id)



    async def run(self, repo:str, pr_number:int, dry_run:bool = False) -> AnalysisResult:
        analysis_id = str(uuid.uuid4())
        logger = StructuredLogger(analysis_id)
        star_time = time.monotonic()

        #logger

        logger.log(
            componente="SecurityAgent",
            evento="Analysis_Sarted",
            repo=repo,
            pr_number=pr_number,
            dry_run=dry_run
        )

        # Extraer el diff actual de GH

        diff_raw = await self.diff_extraction_port.get_diff(repo, pr_number)

        #construir el logg

        logger.log(
            componente="SecurityAgent",
            evento="diff_fecthed",
            chars=len(diff_raw)
        )

        # Parsear el diff
        parser = DiffParser(max_diff_lines=self.config.max_diff_lines)
        parsed = parser.parse(diff_raw)

        # Verificar si el diff esta truncated
        if parsed.diff_truncated:
            logger.log(
                componente="SecurityAgent",
                evento="diff_truncated",
                chars=len(diff_raw),
                max_chars=self.config.max_diff_lines
            )
        # Realizar análisis estático en los archivos modificados

        if len(parsed.manifest_files) > 0:
            sast_results, cve_findings = await asyncio.gather(
                self.static_analysis_port.analyze_diff(diff_raw),
                self.cve_lookup_port.lookup_vulnerabilities(parsed.dependency_changes)
            )

        else:
            sast_results = await self.static_analysis_port.analyze_diff(diff_raw)
            cve_findings = []
            logger.log(
                componente="SecurityAgent",
                evento="no_manifest_files",
                razon ="no_manifiests"
            )


        # log de los resultados del SAST
        logger.log(
            componente="SecurityAgent",
            evento="sast_completed",
            findings_count= len(sast_results.findings),
            errores_parciales=len(sast_results.errores_parciales)
        )

        #log de los resultados del CVE

        logger.log(
            componente="SecurityAgent",
            evento="cve_completed",
            findings_count=len([f for f in cve_findings if isinstance (f, CVEFinding)])
        )

        #Convertir CVE findings y merge candidatos de vulns

        cve_candidates = [
            self._cve_to_candidate(f)
            for f in cve_findings
            if isinstance(f, CVEFinding)
        ]

        all_candidates = cve_candidates + sast_results.findings
        

        #extraer el flah para el AnalysisResult
        dependency_limit_exceeded = any(
            hasattr(f, "tipo") and f.tipo == "limit_exceeded"
            for f in cve_findings
        )

        #Ordenar candidatos
        candidates = sorted(all_candidates, key=lambda x: SEVERITY_ORDER[x.severidad_inicial], reverse=True)


        candidates_for_llm = candidates[: MAX_FINDINGS_LLM]

        #inicializar la lista de confirmed_findings
        confirmed_findings: list[ConfirmedFinding] = []

        #for que recorre los candidatos busca patrones en KB y luego llama al LLM para confirmar

        for candidate in candidates_for_llm:
            kb_frags = await self.kb_retrieval_port.retrieve(candidate)

            #try llm veredict
            try:
                veredict = await self.llm_reasoning_port.evaluate_finding(
                    candidate, kb_frags, self.team_profile
                )
                disposition = "incluido" if veredict.es_explotable else "descartado"
                severidad = veredict.severidad_ajustada
                justificacion = veredict.justificacion
                recomendacion = veredict.recomendacion
            except Exception as e:
                #Fallo del LLM
                disposition = "no_evaluado"
                severidad = candidate.severidad_inicial
                justificacion = f"No evaluado por fallo del LLM: {e}"
                recomendacion = Recommendation(
                    descripcion="Revisión manual recomendada.",
                    codigo_corregido="",
                    referencia=candidate.cwe_id or candidate.cve_id or "",
                )
                logger.log(
                    componente="SecurityAgent",
                    evento="llm_parse_failure",
                    finding_id=candidate.finding_id,
                    error=str(e)
                )

            #confirmed_findings
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

        #dividir los confirmed findings

        duration_seconds = time.monotonic() - star_time

        # Ordenar confirmed_findings por severidad descendente para el resultado final
        confirmed_findings.sort(
            key=lambda f: SEVERITY_ORDER[f.severidad_ajustada], reverse=True
        )

        confirmed = [f for f in confirmed_findings if f.disposition == "incluido"]
        discarded = [f for f in confirmed_findings if f.disposition == "descartado"]
        not_evaluated = [f for f in confirmed_findings if f.disposition == "no_evaluado"]

        #construir el resultado
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

        #Verificar que no es dry-run y publicar comentario
        if not dry_run:
            comment_id = await self.pr_comment_port.post_or_update_comment(repo, pr_number, result)
            result = result.model_copy(update={"comment_id": comment_id})
        else:
            logger.log(
                componente="SecurityAgent",
                evento="comment_skipped",
                razon="dry-run  "
            )

        logger.log(
            componente="SecurityAgent",
            evento="analysis_complete",
            confirmed=len(confirmed),
            discarded=len(discarded),
            not_evaluated=len(not_evaluated),
            duration_seconds=result.duration_seconds,
        )

        return result


    def _cve_to_candidate (self, cve:CVEFinding) -> CandidateFinding:
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "NONE": Severity.INFO
        }

        return CandidateFinding(
            source="cve",
            tipo_vulnerabilidad=cve.descripcion,
            archivo=f"{cve.ecosistema}/{cve.paquete}",
            linea_inicio= 0,
            linea_fin=0,
            fragmento_codigo=f"{cve.paquete} == {cve.version}",
            patron_detectado=cve.cve_id,
            cve_id = cve.cve_id,
            paquete= cve.paquete,
            version = cve.version,
            ecosistema = cve.ecosistema,
            severidad_inicial = severity_map.get(cve.severidad, Severity.MEDIUM)

        )