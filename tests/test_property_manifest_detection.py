"""Property-based tests para la detección de manifiestos de dependencias.

**Validates: Requirements 2.2**

Verifica que solo los nombres canónicos se clasifican como manifiestos
y los demás no, usando Hypothesis con st.sampled_from(MANIFEST_NAMES)
unión st.text().
"""

import os

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from security_pr_guardian.core.manifest_detection import MANIFEST_NAMES, is_manifest


# Estrategia: nombres canónicos de manifiesto
manifest_names_strategy = st.sampled_from(sorted(MANIFEST_NAMES))

# Estrategia: texto arbitrario que NO es un nombre de manifiesto
non_manifest_strategy = st.text(min_size=0, max_size=100).filter(
    lambda x: os.path.basename(x) not in MANIFEST_NAMES
)

# Estrategia: ruta con directorio prefijo + nombre de manifiesto
path_with_manifest_strategy = st.tuples(
    st.text(
        alphabet=st.characters(blacklist_characters="\x00/\\"),
        min_size=1,
        max_size=30,
    ),
    manifest_names_strategy,
).map(lambda t: f"{t[0]}/{t[1]}")


class TestManifestDetectionProperty:
    """Property 9: Detección de manifiestos exacta por nombre."""

    @settings(max_examples=100)
    @given(name=manifest_names_strategy)
    def test_canonical_names_always_detected(self, name: str) -> None:
        """Todo nombre canónico de manifiesto debe ser detectado como tal."""
        assert is_manifest(name) is True

    @settings(max_examples=100)
    @given(text=non_manifest_strategy)
    def test_non_manifest_names_never_detected(self, text: str) -> None:
        """Ningún texto fuera del conjunto canónico debe ser detectado como manifiesto."""
        assert is_manifest(text) is False

    @settings(max_examples=100)
    @given(path=path_with_manifest_strategy)
    def test_manifest_detected_with_directory_prefix(self, path: str) -> None:
        """Un nombre canónico precedido de una ruta de directorio sigue siendo detectado."""
        assert is_manifest(path) is True

    @settings(max_examples=100)
    @given(
        prefix=st.text(
            alphabet=st.characters(blacklist_characters="\x00/\\"),
            min_size=1,
            max_size=10,
        ),
        name=manifest_names_strategy,
    )
    def test_modified_name_not_detected(self, prefix: str, name: str) -> None:
        """Un nombre canónico con prefijo extra no debe ser detectado como manifiesto."""
        modified = prefix + name
        assume(modified not in MANIFEST_NAMES)
        assert is_manifest(modified) is False
