# security_pr_guardian/ports/__init__.py
"""Puertos (interfaces) del núcleo hexagonal de Security PR Guardian."""

from security_pr_guardian.ports.DiffExtractionPort import DiffExtractionPort
from security_pr_guardian.ports.StaticAnalysisPort import StaticAnalysisPort
from security_pr_guardian.ports.CVEPort import CVEPort
from security_pr_guardian.ports.KBRetrievalPort import KBRetrievalPort
from security_pr_guardian.ports.LLMReasoningPort import LLMReasoningPort
from security_pr_guardian.ports.PRCommentPort import PRCommentPort

__all__ = [
    "DiffExtractionPort",
    "StaticAnalysisPort",
    "CVELookupPort",
    "KBRetrievalPort",
    "LLMReasoningPort",
    "PRCommentPort",
]