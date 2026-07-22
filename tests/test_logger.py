"""Unit tests for StructuredLogger."""

import io
import json

from security_pr_guardian.core.logger import StructuredLogger
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
