"""Property-based tests para el DiffParser — invariante de truncación.

**Validates: Requirements 2.6**

**Property 5**: Para cualquier diff con N líneas añadidas donde
N > max_diff_lines, se verifica que:
- `diff_truncated=True`
- Ningún `CandidateFinding.linea_inicio` referencia contenido más allá
  del límite de truncación.
- El número de líneas añadidas procesadas es exactamente `max_diff_lines`.
"""

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from security_pr_guardian.core.diff_parser import DiffParser
from security_pr_guardian.adapters.mcp.pattern_engine import PatternEngine


def _build_diff_with_n_added_lines(n: int, include_vulnerability: bool = True) -> str:
    """Genera un diff sintético con exactamente N líneas añadidas.

    Si include_vulnerability=True, incluye un patrón SQL injection
    en varias posiciones para que el PatternEngine genere findings.
    """
    lines = [
        "diff --git a/app/main.py b/app/main.py",
        "--- /dev/null",
        "+++ b/app/main.py",
        f"@@ -0,0 +1,{n} @@",
    ]

    for i in range(1, n + 1):
        if include_vulnerability and i % 500 == 0:
            # Inject SQL injection pattern at predictable positions
            lines.append(f'+query = f"SELECT * FROM users WHERE id = {{user_id}}"  # line {i}')
        else:
            lines.append(f"+# safe code line {i}")

    return "\n".join(lines)


class TestDiffTruncationProperty:
    """Property 5: Invariante de truncación de diff."""

    @settings(max_examples=100)
    @given(n_lines=st.integers(min_value=9990, max_value=15000))
    def test_truncation_flag_when_exceeds_limit(self, n_lines: int) -> None:
        """Cuando N > max_diff_lines, diff_truncated siempre es True.

        Y cuando N <= max_diff_lines, diff_truncated siempre es False.
        """
        max_diff_lines = 10_000
        diff = _build_diff_with_n_added_lines(n_lines)
        parser = DiffParser(max_diff_lines=max_diff_lines)
        result = parser.parse(diff)

        if n_lines > max_diff_lines:
            assert result.diff_truncated is True, (
                f"Expected diff_truncated=True for {n_lines} lines "
                f"(limit={max_diff_lines})"
            )
        else:
            assert result.diff_truncated is False, (
                f"Expected diff_truncated=False for {n_lines} lines "
                f"(limit={max_diff_lines})"
            )

    @settings(max_examples=100)
    @given(n_lines=st.integers(min_value=9990, max_value=15000))
    def test_processed_lines_never_exceed_limit(self, n_lines: int) -> None:
        """El número de líneas procesadas nunca excede max_diff_lines."""
        max_diff_lines = 10_000
        diff = _build_diff_with_n_added_lines(n_lines)
        parser = DiffParser(max_diff_lines=max_diff_lines)
        result = parser.parse(diff)

        assert len(result.added_lines) <= max_diff_lines, (
            f"Processed {len(result.added_lines)} lines but limit is {max_diff_lines}"
        )

    @settings(max_examples=100)
    @given(n_lines=st.integers(min_value=10001, max_value=15000))
    def test_no_findings_beyond_truncation_limit(self, n_lines: int) -> None:
        """Ningún CandidateFinding.linea_inicio referencia contenido
        más allá del límite de truncación.

        Usa el PatternEngine real para generar findings sobre el diff
        truncado y verifica que las líneas reportadas están dentro del
        rango válido.
        """
        max_diff_lines = 10_000
        diff = _build_diff_with_n_added_lines(n_lines, include_vulnerability=True)

        # Truncate the diff first (simulating what the agent pipeline does)
        parser = DiffParser(max_diff_lines=max_diff_lines)
        truncated_diff, was_truncated = parser.truncate_diff(diff)

        assert was_truncated is True

        # Run pattern engine on the truncated diff
        engine = PatternEngine()
        analysis_result = engine.analyze(truncated_diff)

        # Verify no finding references a line beyond the truncation limit
        for finding in analysis_result.findings:
            assert finding.linea_inicio <= max_diff_lines, (
                f"Finding at line {finding.linea_inicio} exceeds "
                f"truncation limit {max_diff_lines}"
            )
            assert finding.linea_fin <= max_diff_lines, (
                f"Finding linea_fin={finding.linea_fin} exceeds "
                f"truncation limit {max_diff_lines}"
            )

    @settings(max_examples=100)
    @given(n_lines=st.integers(min_value=10001, max_value=15000))
    def test_parse_result_lines_within_limit(self, n_lines: int) -> None:
        """Todas las líneas en added_lines tienen line_number <= max_diff_lines."""
        max_diff_lines = 10_000
        diff = _build_diff_with_n_added_lines(n_lines)
        parser = DiffParser(max_diff_lines=max_diff_lines)
        result = parser.parse(diff)

        for parsed_line in result.added_lines:
            assert parsed_line.line_number <= max_diff_lines, (
                f"ParsedLine.line_number={parsed_line.line_number} exceeds "
                f"truncation limit {max_diff_lines}"
            )

    @settings(max_examples=100)
    @given(n_lines=st.integers(min_value=9990, max_value=15000))
    def test_total_added_lines_reflects_actual_count(self, n_lines: int) -> None:
        """total_added_lines siempre refleja el conteo real de líneas,
        incluso cuando se trunca.
        """
        max_diff_lines = 10_000
        diff = _build_diff_with_n_added_lines(n_lines)
        parser = DiffParser(max_diff_lines=max_diff_lines)
        result = parser.parse(diff)

        assert result.total_added_lines == n_lines, (
            f"total_added_lines={result.total_added_lines} but expected {n_lines}"
        )
