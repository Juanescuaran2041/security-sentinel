"""Puertos (interfaces abstractas) del sistema Security PR Guardian.

Cada puerto define un contrato que los adaptadores deben implementar,
siguiendo la arquitectura hexagonal (Ports & Adapters).
"""

from security_pr_guardian.ports.cve_lookup import CVELookupPort
from security_pr_guardian.ports.diff_extraction import DiffExtractionPort
from security_pr_guardian.ports.kb_retrieval import KBRetrievalPort
from security_pr_guardian.ports.llm_reasoning import LLMReasoningPort
from security_pr_guardian.ports.pr_comment import PRCommentPort
from security_pr_guardian.ports.static_analysis import StaticAnalysisPort

__all__ = [
    "CVELookupPort",
    "DiffExtractionPort",
    "KBRetrievalPort",
    "LLMReasoningPort",
    "PRCommentPort",
    "StaticAnalysisPort",
]
