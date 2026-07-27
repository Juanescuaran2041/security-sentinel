"""Structured JSON logger for Security PR Guardian pipeline observability.

Provides both a generic `log()` method and convenience methods for lifecycle
events defined in the design. Convenience methods enforce the rule that
`duracion_ms` is present if and only if the event represents a completed
operation with measurable start and end.
"""

import json
import sys
from typing import Any

from security_pr_guardian.core.models import LogEvent


# Events that represent completed timed operations — duracion_ms is required.
_TIMED_EVENTS: frozenset[str] = frozenset({
    "analysis_complete",
    "llm_call_complete",
    "kb_retrieval_complete",
    "static_analysis_complete",
    "cve_lookup_complete",
    "diff_fetch_complete",
    "comment_publish_complete",
})

# Events that are instantaneous notifications — duracion_ms must be absent.
_INSTANT_EVENTS: frozenset[str] = frozenset({
    "analysis_failed",
    "comment_publish_failed",
    "diff_truncated",
    "kb_timeout",
    "llm_parse_failure",
    "finding_evaluated",
    "analysis_started",
    "limit_exceeded",
})


class StructuredLogger:
    """Emits structured log events as JSON lines to stderr.

    Each event is validated via the LogEvent Pydantic model before emission.
    The analysis_id is propagated to every event automatically, enabling
    end-to-end tracing of a single analysis run.

    Parameters
    ----------
    analysis_id : str
        UUID v4 identifying the current analysis run.
    output : file-like, optional
        Writable stream for log output. Defaults to sys.stderr so logs
        don't interfere with --output json on stdout.
    """

    def __init__(self, analysis_id: str, output=None):
        self._analysis_id = analysis_id
        self._output = output or sys.stderr

    @property
    def analysis_id(self) -> str:
        return self._analysis_id

    def log(
        self,
        componente: str,
        evento: str,
        duracion_ms: int | None = None,
        **detalle: Any,
    ) -> LogEvent:
        """Construct, validate, and emit a structured log event.

        Parameters
        ----------
        componente : str
            Which component emitted the event (e.g. "Static_Analyzer").
        evento : str
            What happened (e.g. "analysis_started").
        duracion_ms : int | None
            Elapsed milliseconds for timed operations. Omit for non-timed events.
        **detalle : Any
            Arbitrary key-value pairs providing additional context.

        Returns
        -------
        LogEvent
            The validated event instance (useful for testing).

        Raises
        ------
        ValueError
            If duracion_ms is provided for an instant-only event, or omitted
            for a timed-only event.
        """
        # Enforce duracion_ms rule for known events
        if evento in _TIMED_EVENTS and duracion_ms is None:
            raise ValueError(
                f"Event '{evento}' represents a completed operation and "
                f"requires duracion_ms."
            )
        if evento in _INSTANT_EVENTS and duracion_ms is not None:
            raise ValueError(
                f"Event '{evento}' is instantaneous and must not have "
                f"duracion_ms."
            )

        log_event = LogEvent(
            analysis_id=self._analysis_id,
            componente=componente,
            evento=evento,
            duracion_ms=duracion_ms,
            detalle=detalle,
        )

        # Serialize to JSON line; exclude None fields to keep output clean
        json_line = log_event.model_dump_json(exclude_none=True)
        self._output.write(json_line + "\n")
        self._output.flush()

        return log_event

    # ------------------------------------------------------------------
    # Convenience methods for lifecycle events
    # ------------------------------------------------------------------

    def analysis_complete(
        self,
        duracion_ms: int,
        *,
        candidate_count: int,
        confirmed_count: int,
        discarded_count: int,
        not_evaluated_count: int,
    ) -> LogEvent:
        """Emit event when full analysis pipeline completes successfully."""
        return self.log(
            "Security_Agent",
            "analysis_complete",
            duracion_ms=duracion_ms,
            candidate_count=candidate_count,
            confirmed_count=confirmed_count,
            discarded_count=discarded_count,
            not_evaluated_count=not_evaluated_count,
        )

    def analysis_failed(
        self,
        *,
        error: str,
        stage: str,
    ) -> LogEvent:
        """Emit event when the analysis pipeline fails unrecoverably."""
        return self.log(
            "Security_Agent",
            "analysis_failed",
            error=error,
            stage=stage,
        )

    def comment_publish_failed(
        self,
        *,
        error: str,
        attempts: int,
    ) -> LogEvent:
        """Emit event when PR comment publishing fails after retries."""
        return self.log(
            "PR_Commenter",
            "comment_publish_failed",
            error=error,
            attempts=attempts,
        )

    def diff_truncated(
        self,
        *,
        original_lines: int,
        max_lines: int,
    ) -> LogEvent:
        """Emit event when the diff exceeds max_diff_lines and is truncated."""
        return self.log(
            "Diff_Parser",
            "diff_truncated",
            original_lines=original_lines,
            max_lines=max_lines,
        )

    def kb_timeout(
        self,
        *,
        timeout_seconds: float,
        finding_id: str,
    ) -> LogEvent:
        """Emit event when KB retrieval times out."""
        return self.log(
            "KB_Retriever",
            "kb_timeout",
            timeout_seconds=timeout_seconds,
            finding_id=finding_id,
        )

    def llm_parse_failure(
        self,
        *,
        finding_id: str,
        raw_response: str,
        error: str,
    ) -> LogEvent:
        """Emit event when LLM response cannot be parsed as valid JSON."""
        return self.log(
            "Bedrock_Client",
            "llm_parse_failure",
            finding_id=finding_id,
            raw_response=raw_response[:500],  # Truncate for log safety
            error=error,
        )

    def finding_evaluated(
        self,
        *,
        finding_id: str,
        es_explotable: bool,
        severidad_ajustada: str,
        justificacion: str,
        disposition: str,
    ) -> LogEvent:
        """Emit event for each finding after LLM evaluation."""
        return self.log(
            "Security_Agent",
            "finding_evaluated",
            finding_id=finding_id,
            es_explotable=es_explotable,
            severidad_ajustada=severidad_ajustada,
            justificacion=justificacion,
            disposition=disposition,
        )
