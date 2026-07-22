"""Structured JSON logger for Security PR Guardian pipeline observability."""

import json
import sys
from typing import Any

from security_pr_guardian.core.models import LogEvent


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
        """
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
