"""Unit tests for StructuredLogger."""

import io
import json
from uuid import uuid4

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from security_pr_guardian.core.logger import (
    StructuredLogger,
    _INSTANT_EVENTS,
    _TIMED_EVENTS,
)
from security_pr_guardian.core.models import LogEvent


class TestStructuredLogger:
    """Tests for the StructuredLogger class."""

    def _make_logger(self, analysis_id: str = "550e8400-e29b-41d4-a716-446655440000"):
        buf = io.StringIO()
        logger = StructuredLogger(analysis_id=analysis_id, output=buf)
        return logger, buf

    def test_emits_json_line_with_required_fields(self):
        logger, buf = self._make_logger()
        logger.log("Static_Analyzer", "analysis_started", file="main.py")

        line = json.loads(buf.getvalue().strip())
        assert line["analysis_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert line["componente"] == "Static_Analyzer"
        assert line["evento"] == "analysis_started"
        assert line["detalle"] == {"file": "main.py"}
        assert "timestamp" in line

    def test_duration_ms_excluded_when_none(self):
        logger, buf = self._make_logger()
        logger.log("Static_Analyzer", "analysis_started")

        line = json.loads(buf.getvalue().strip())
        assert "duracion_ms" not in line

    def test_duration_ms_included_when_provided(self):
        logger, buf = self._make_logger()
        logger.log("Bedrock_Client", "llm_call_complete", duracion_ms=1234, model="claude-3")

        line = json.loads(buf.getvalue().strip())
        assert line["duracion_ms"] == 1234
        assert line["detalle"] == {"model": "claude-3"}

    def test_returns_log_event_instance(self):
        logger, _ = self._make_logger()
        evt = logger.log("KB_Retriever", "retrieval_done", chunks=5)

        assert isinstance(evt, LogEvent)
        assert evt.componente == "KB_Retriever"
        assert evt.evento == "retrieval_done"
        assert evt.detalle == {"chunks": 5}

    def test_analysis_id_property(self):
        logger, _ = self._make_logger("test-id-123")
        assert logger.analysis_id == "test-id-123"

    def test_multiple_events_emit_multiple_lines(self):
        logger, buf = self._make_logger()
        logger.log("A", "event_1")
        logger.log("B", "event_2")

        lines = buf.getvalue().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["componente"] == "A"
        assert json.loads(lines[1])["componente"] == "B"

    def test_timestamp_is_iso_format(self):
        logger, buf = self._make_logger()
        logger.log("Security_Agent", "started")

        line = json.loads(buf.getvalue().strip())
        # ISO 8601 timestamps contain 'T' separator and end with timezone info
        assert "T" in line["timestamp"]

    def test_empty_details_when_no_kwargs(self):
        logger, buf = self._make_logger()
        logger.log("PR_Commenter", "comment_posted")

        line = json.loads(buf.getvalue().strip())
        assert line["detalle"] == {}


class TestStructuredLoggerLifecycleEvents:
    """Tests for convenience lifecycle methods and duracion_ms enforcement."""

    def _make_logger(self, analysis_id: str = "550e8400-e29b-41d4-a716-446655440000"):
        buf = io.StringIO()
        logger = StructuredLogger(analysis_id=analysis_id, output=buf)
        return logger, buf

    # ------------------------------------------------------------------
    # 9.3 — Required base fields present in every event
    # ------------------------------------------------------------------

    def test_all_events_have_required_base_fields(self):
        """Every emitted event must contain timestamp, analysis_id,
        componente, evento, and detalle."""
        logger, buf = self._make_logger()
        logger.log("TestComp", "custom_event", key="val")

        line = json.loads(buf.getvalue().strip())
        required = {"timestamp", "analysis_id", "componente", "evento", "detalle"}
        assert required.issubset(line.keys())

    # ------------------------------------------------------------------
    # 9.3 — duracion_ms enforcement
    # ------------------------------------------------------------------

    def test_timed_event_raises_without_duracion_ms(self):
        """Timed events (e.g. analysis_complete) must require duracion_ms."""
        logger, _ = self._make_logger()
        with pytest.raises(ValueError, match="requires duracion_ms"):
            logger.log("Security_Agent", "analysis_complete")

    def test_instant_event_raises_with_duracion_ms(self):
        """Instant events (e.g. analysis_failed) must reject duracion_ms."""
        logger, _ = self._make_logger()
        with pytest.raises(ValueError, match="must not have"):
            logger.log("Security_Agent", "analysis_failed", duracion_ms=100)

    def test_unknown_event_allows_optional_duracion_ms(self):
        """Events not in either set allow duracion_ms to be optional."""
        logger, buf = self._make_logger()
        # Without duracion_ms — should work
        evt1 = logger.log("X", "some_custom_event")
        assert evt1.duracion_ms is None
        # With duracion_ms — should also work
        evt2 = logger.log("X", "some_custom_event", duracion_ms=42)
        assert evt2.duracion_ms == 42

    # ------------------------------------------------------------------
    # 9.3 — analysis_complete convenience method
    # ------------------------------------------------------------------

    def test_analysis_complete_emits_all_counts(self):
        """analysis_complete must emit candidate/confirmed/discarded/not_evaluated."""
        logger, buf = self._make_logger()
        evt = logger.analysis_complete(
            duracion_ms=5000,
            candidate_count=15,
            confirmed_count=3,
            discarded_count=10,
            not_evaluated_count=2,
        )

        assert evt.evento == "analysis_complete"
        assert evt.componente == "Security_Agent"
        assert evt.duracion_ms == 5000
        assert evt.detalle["candidate_count"] == 15
        assert evt.detalle["confirmed_count"] == 3
        assert evt.detalle["discarded_count"] == 10
        assert evt.detalle["not_evaluated_count"] == 2

    def test_analysis_complete_json_has_duracion_ms(self):
        logger, buf = self._make_logger()
        logger.analysis_complete(
            duracion_ms=1200,
            candidate_count=5,
            confirmed_count=1,
            discarded_count=3,
            not_evaluated_count=1,
        )
        line = json.loads(buf.getvalue().strip())
        assert line["duracion_ms"] == 1200

    # ------------------------------------------------------------------
    # 9.3 — analysis_failed convenience method
    # ------------------------------------------------------------------

    def test_analysis_failed_emits_error_and_stage(self):
        logger, buf = self._make_logger()
        evt = logger.analysis_failed(error="Connection timeout", stage="diff_fetch")

        assert evt.evento == "analysis_failed"
        assert evt.componente == "Security_Agent"
        assert evt.duracion_ms is None
        assert evt.detalle["error"] == "Connection timeout"
        assert evt.detalle["stage"] == "diff_fetch"

    def test_analysis_failed_no_duracion_ms_in_json(self):
        logger, buf = self._make_logger()
        logger.analysis_failed(error="Boom", stage="llm")
        line = json.loads(buf.getvalue().strip())
        assert "duracion_ms" not in line

    # ------------------------------------------------------------------
    # 9.3 — comment_publish_failed convenience method
    # ------------------------------------------------------------------

    def test_comment_publish_failed(self):
        logger, _ = self._make_logger()
        evt = logger.comment_publish_failed(error="403 Forbidden", attempts=3)

        assert evt.evento == "comment_publish_failed"
        assert evt.componente == "PR_Commenter"
        assert evt.detalle["error"] == "403 Forbidden"
        assert evt.detalle["attempts"] == 3
        assert evt.duracion_ms is None

    # ------------------------------------------------------------------
    # 9.3 — diff_truncated convenience method
    # ------------------------------------------------------------------

    def test_diff_truncated_event(self):
        logger, _ = self._make_logger()
        evt = logger.diff_truncated(original_lines=15000, max_lines=10000)

        assert evt.evento == "diff_truncated"
        assert evt.componente == "Diff_Parser"
        assert evt.detalle["original_lines"] == 15000
        assert evt.detalle["max_lines"] == 10000
        assert evt.duracion_ms is None

    # ------------------------------------------------------------------
    # 9.3 — kb_timeout convenience method
    # ------------------------------------------------------------------

    def test_kb_timeout_event(self):
        logger, _ = self._make_logger()
        evt = logger.kb_timeout(timeout_seconds=5.0, finding_id="f-123")

        assert evt.evento == "kb_timeout"
        assert evt.componente == "KB_Retriever"
        assert evt.detalle["timeout_seconds"] == 5.0
        assert evt.detalle["finding_id"] == "f-123"
        assert evt.duracion_ms is None

    # ------------------------------------------------------------------
    # 9.3 — llm_parse_failure convenience method
    # ------------------------------------------------------------------

    def test_llm_parse_failure_event(self):
        logger, _ = self._make_logger()
        evt = logger.llm_parse_failure(
            finding_id="f-456",
            raw_response="not json at all",
            error="JSONDecodeError",
        )

        assert evt.evento == "llm_parse_failure"
        assert evt.componente == "Bedrock_Client"
        assert evt.detalle["finding_id"] == "f-456"
        assert evt.detalle["raw_response"] == "not json at all"
        assert evt.detalle["error"] == "JSONDecodeError"
        assert evt.duracion_ms is None

    def test_llm_parse_failure_truncates_raw_response(self):
        logger, _ = self._make_logger()
        long_response = "x" * 1000
        evt = logger.llm_parse_failure(
            finding_id="f-789",
            raw_response=long_response,
            error="too long",
        )
        # raw_response in detalle should be truncated to 500 chars
        assert len(evt.detalle["raw_response"]) == 500

    # ------------------------------------------------------------------
    # 9.3 — finding_evaluated convenience method
    # ------------------------------------------------------------------

    def test_finding_evaluated_event(self):
        logger, _ = self._make_logger()
        evt = logger.finding_evaluated(
            finding_id="f-001",
            es_explotable=True,
            severidad_ajustada="high",
            justificacion="User input flows directly into SQL query",
            disposition="incluido",
        )

        assert evt.evento == "finding_evaluated"
        assert evt.componente == "Security_Agent"
        assert evt.detalle["finding_id"] == "f-001"
        assert evt.detalle["es_explotable"] is True
        assert evt.detalle["severidad_ajustada"] == "high"
        assert evt.detalle["disposition"] == "incluido"
        assert evt.duracion_ms is None

    # ------------------------------------------------------------------
    # 9.3 — duracion_ms present only when appropriate (parametrized)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("evento", list(_TIMED_EVENTS))
    def test_timed_events_require_duracion_ms(self, evento):
        logger, _ = self._make_logger()
        with pytest.raises(ValueError, match="requires duracion_ms"):
            logger.log("AnyComponent", evento)

    @pytest.mark.parametrize("evento", list(_INSTANT_EVENTS))
    def test_instant_events_reject_duracion_ms(self, evento):
        logger, _ = self._make_logger()
        with pytest.raises(ValueError, match="must not have"):
            logger.log("AnyComponent", evento, duracion_ms=100)


# ======================================================================
# 9.4 — Property-based test (Hypothesis)
# Property 14: Los eventos de log siempre contienen los campos base
# requeridos (timestamp, analysis_id, componente, evento, detalle)
# ======================================================================


class TestLogEventProperty:
    """Property-based tests for LogEvent base field invariants."""

    @given(
        analysis_id=st.from_regex(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            fullmatch=True,
        ),
        componente=st.text(min_size=1, max_size=50, alphabet=st.characters(categories=("L", "N", "P"))),
        evento=st.text(min_size=1, max_size=50, alphabet=st.characters(categories=("L", "N", "P"))),
        duracion_ms=st.one_of(st.none(), st.integers(min_value=0, max_value=3_600_000)),
    )
    @settings(max_examples=100)
    def test_log_event_always_has_required_base_fields(
        self, analysis_id, componente, evento, duracion_ms
    ):
        """Property 14: LogEvent instances always contain timestamp,
        analysis_id, componente, evento, and detalle — regardless of
        input values."""
        log_event = LogEvent(
            analysis_id=analysis_id,
            componente=componente,
            evento=evento,
            duracion_ms=duracion_ms,
            detalle={"sample": "data"},
        )

        # Validate required fields are present and correctly typed
        assert log_event.timestamp is not None
        assert log_event.analysis_id == analysis_id
        assert log_event.componente == componente
        assert log_event.evento == evento
        assert isinstance(log_event.detalle, dict)

        # Validate JSON serialization preserves required fields
        dumped = json.loads(log_event.model_dump_json(exclude_none=True))
        assert "timestamp" in dumped
        assert "analysis_id" in dumped
        assert "componente" in dumped
        assert "evento" in dumped
        assert "detalle" in dumped

        # duracion_ms should only be in JSON when not None
        if duracion_ms is None:
            assert "duracion_ms" not in dumped
        else:
            assert dumped["duracion_ms"] == duracion_ms

    @given(
        componente=st.text(min_size=1, max_size=30, alphabet=st.characters(categories=("L",))),
        evento=st.sampled_from(list(_INSTANT_EVENTS | _TIMED_EVENTS) + ["custom_event"]),
    )
    @settings(max_examples=100)
    def test_structured_logger_always_emits_base_fields(self, componente, evento):
        """Property 14 via StructuredLogger: emitted JSON always contains
        the 5 required base fields."""
        buf = io.StringIO()
        logger = StructuredLogger(analysis_id=str(uuid4()), output=buf)

        # Provide duracion_ms only when required by timed events
        kwargs: dict = {}
        if evento in _TIMED_EVENTS:
            kwargs["duracion_ms"] = 100

        logger.log(componente, evento, **kwargs)

        line = json.loads(buf.getvalue().strip())
        required_keys = {"timestamp", "analysis_id", "componente", "evento", "detalle"}
        assert required_keys.issubset(line.keys())
