"""Tests de propiedad (Property-Based Testing) para KB_Retriever.

Tareas:
  5.4 — Property 7: KB retorna como máximo top_k fragmentos
        Para cualquier top_k entre 1 y 10, se cumple 0 ≤ len(result) ≤ top_k.

  5.5 — Property 11: score_relevancia siempre en [0.0, 1.0]
        Para cualquier KBFragment construido, 0.0 ≤ score_relevancia ≤ 1.0.

¿Qué hace Hypothesis?
  En lugar de elegir vos los datos de prueba, Hypothesis los genera aleatoriamente.
  @given(st.integers(min_value=1, max_value=10)) le dice a Hypothesis:
  "ejecutá este test 100 veces con un entero distinto entre 1 y 10 cada vez".
  Si algún valor falla, Hypothesis te muestra exactamente cuál fue.

Estrategia de mocking para 5.4:
  - El adapter se configura igual que en test_chroma_kb_adapter.py.
  - Se controla cuántos documentos "tiene" la KB con count.return_value.
  - Se controla qué devuelve query con make_chroma_results().
  - El top_k varía en cada ejecución — eso es lo que genera Hypothesis.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from security_pr_guardian.adapters.kb.chroma_adapter import ChromaKBAdapter
from security_pr_guardian.core.models import CandidateFinding, KBFragment, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_chroma_results(distances: list[float]) -> dict:
    """Mismo helper que en test_chroma_kb_adapter.py — formato que devuelve ChromaDB."""
    n = len(distances)
    return {
        "documents": [[f"contenido documento {i}" for i in range(n)]],
        "metadatas": [[{"titulo": f"Doc {i}", "fuente": f"src/doc{i}.md"} for i in range(n)]],
        "distances": [distances],
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_finding() -> CandidateFinding:
    return CandidateFinding(
        source="static",
        tipo_vulnerabilidad="SQL Injection",
        archivo="app/db.py",
        linea_inicio=42,
        linea_fin=42,
        fragmento_codigo='cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
        patron_detectado="string formatting in SQL query",
        cwe_id="CWE-89",
        severidad_inicial=Severity.HIGH,
    )


# ---------------------------------------------------------------------------
# Property 7: KB retorna como máximo top_k fragmentos
# ---------------------------------------------------------------------------


@given(st.integers(min_value=1, max_value=10))
@settings(max_examples=100)
def test_kb_returns_at_most_top_k_fragments(top_k):
    """
    PROPIEDAD: para cualquier top_k entre 1 y 10, la cantidad de fragmentos
    retornados cumple 0 ≤ len(result) ≤ top_k.

    Cómo funciona:
      - Hypothesis llama a este test 100 veces con un top_k distinto cada vez.
      - La KB tiene exactamente top_k documentos disponibles (el caso máximo).
      - Se generan top_k distancias de 0.5 (scores neutros, no importa el valor).
      - Se verifica que len(result) no supera top_k.

    Pistas:
      - Creá el adapter y configurá los mocks igual que en test_chroma_kb_adapter.py.
      - adapter._collection.count.return_value = top_k
      - make_chroma_results([0.5] * top_k) genera top_k resultados con distancia 0.5
      - Como este test NO es async, usá asyncio.run(adapter.retrieve(...)) en lugar de await
      - Verificá: 0 <= len(result) <= top_k
    """
    scores = make_chroma_results([0.5] * top_k)

    adapter = ChromaKBAdapter(logger=None)
    adapter._initialized = True
    adapter._model = MagicMock()
    adapter._collection = MagicMock()

    adapter._collection.count.return_value = top_k
    adapter._collection.query.return_value = scores
    adapter._model.encode.return_value = [0.1] * 384

    finding = CandidateFinding(
        source="static",
        tipo_vulnerabilidad="SQL Injection",
        archivo="app/db.py",
        linea_inicio=42,
        linea_fin=42,
        fragmento_codigo="cursor.execute(query % user_id)",
        patron_detectado="string formatting in SQL",
        cwe_id="CWE-89",
        severidad_inicial=Severity.HIGH,
    )
    result = asyncio.run(adapter.retrieve(finding, top_k))

    assert 0 <= len(result) <= top_k

# ---------------------------------------------------------------------------
# Property 11: score_relevancia siempre en [0.0, 1.0]
# ---------------------------------------------------------------------------


@given(
    st.builds(
        KBFragment,
        titulo=st.text(min_size=1, max_size=50),
        contenido=st.text(min_size=1, max_size=200),
        fuente=st.text(min_size=1, max_size=100),
        score_relevancia=st.floats(min_value=0.0, max_value=1.0),
        baja_confianza=st.booleans(),
    )
)
@settings(max_examples=100)
def test_score_relevancia_always_in_bounds(fragment: KBFragment):
    """
    PROPIEDAD: para cualquier KBFragment, score_relevancia siempre está en [0.0, 1.0].

    Cómo funciona:
      - Hypothesis construye KBFragment con valores aleatorios en cada ejecución.
      - st.builds(KBFragment, ...) le dice a Hypothesis cómo construir el objeto:
        cada campo recibe su propia strategy para generar valores aleatorios.
      - score_relevancia usa st.floats(min_value=0.0, max_value=1.0) — Hypothesis
        solo genera floats dentro de ese rango.

    Pistas:
      - Este test es muy simple: solo verificá que fragment.score_relevancia
        esté dentro de [0.0, 1.0].
      - NO es async, NO necesita mocks — solo trabaja con el objeto fragment
        que Hypothesis construyó.
      - Verificá: 0.0 <= fragment.score_relevancia <= 1.0
    """
    
    assert 0.0 <= fragment.score_relevancia <= 1.0



# ---------------------------------------------------------------------------
# Property 12: Fragmentos de baja confianza siempre marcados
# ---------------------------------------------------------------------------


@given(
    st.lists(
        st.floats(min_value=0.0, max_value=0.499),
        min_size=1,
        max_size=10,
    )
)
@settings(max_examples=100)
def test_low_confidence_fragments_always_marked(low_scores):
    """
    PROPIEDAD: cuando TODOS los scores son < 0.5, cada fragmento retornado
    tiene baja_confianza=True.

    Cómo funciona:
      - Hypothesis genera una lista de floats entre 0.0 y 0.499 (todos bajos).
      - Cada float de esa lista se convierte en una distancia para ChromaDB.
      - score = 1 - (distance / 2), y como distance está en [0.0, 0.499],
        el score queda en [0.75, 1.0]... espera, eso no es < 0.5.

      IMPORTANTE — la conversión va al revés:
        Para que score < 0.5, necesitás distance > 1.0.
        score = 1 - (distance / 2) < 0.5  →  distance > 1.0

      Entonces los `low_scores` que genera Hypothesis son los SCORES finales
      (< 0.5), pero necesitás convertirlos a DISTANCIAS para ChromaDB:
        distance = (1 - score) * 2

      Ejemplo: score=0.3 → distance = (1 - 0.3) * 2 = 1.4

    Pistas:
      - Convertí low_scores a distancias: distances = [(1 - s) * 2 for s in low_scores]
      - Creá el adapter con los mocks de siempre
      - adapter._collection.count.return_value = len(low_scores)
      - adapter._collection.query.return_value = make_chroma_results(distances)
      - Construí el finding igual que en el test anterior
      - result = asyncio.run(adapter.retrieve(finding, top_k=len(low_scores)))
      - Verificá que todos los fragmentos tienen baja_confianza=True
    """
    distances = [(1 - i) * 2 for i in low_scores]
    adapter = ChromaKBAdapter(logger=None)
    adapter._initialized = True
    adapter._model = MagicMock()
    adapter._collection = MagicMock()

    adapter._collection.count.return_value = len(low_scores)
    adapter._collection.query.return_value = make_chroma_results(distances)
    adapter._model.encode.return_value = [0.1] * 384

    finding = CandidateFinding(
        source="static",
        tipo_vulnerabilidad="SQL Injection",
        archivo="app/db.py",
        linea_inicio=42,
        linea_fin=42,
        fragmento_codigo="cursor.execute(query % user_id)",
        patron_detectado="string formatting in SQL",
        cwe_id="CWE-89",
        severidad_inicial=Severity.HIGH,
    )
    result = asyncio.run(adapter.retrieve(finding, top_k=len(low_scores)))

    for fragment in result:
        assert fragment.baja_confianza is True



# ---------------------------------------------------------------------------
# Property 13: Timeout de KB retorna lista vacía
# ---------------------------------------------------------------------------


@given(
    st.builds(
        CandidateFinding,
        source=st.just("static"),
        tipo_vulnerabilidad=st.text(min_size=1, max_size=50),
        archivo=st.text(min_size=1, max_size=100),
        linea_inicio=st.integers(min_value=1, max_value=10000),
        linea_fin=st.integers(min_value=1, max_value=10000),
        fragmento_codigo=st.text(min_size=0, max_size=500),
        patron_detectado=st.text(min_size=1, max_size=100),
        cwe_id=st.just("CWE-89"),
        cve_id=st.none(),
        paquete=st.none(),
        version=st.none(),
        ecosistema=st.none(),
        severidad_inicial=st.just(Severity.HIGH),
    )
)
@settings(max_examples=5, deadline=None)
def test_kb_timeout_always_returns_empty_list(finding: CandidateFinding):
    """
    PROPIEDAD: para cualquier CandidateFinding, si el retrieve excede el
    timeout de 5s, el resultado es siempre [] (nunca resultados parciales).

    Cómo funciona:
      - Hypothesis construye un CandidateFinding con valores aleatorios.
      - Se mockea _async_retrieve para que duerma 10 segundos (más que el timeout).
      - Se verifica que el resultado es siempre una lista vacía.

    Pistas:
      - Usá patch.object igual que en test_empty_list_on_timeout:
          from unittest.mock import patch, AsyncMock
          async def slow(*args, **kwargs):
              await asyncio.sleep(10)
          with patch.object(adapter, "_async_retrieve", new_callable=AsyncMock) as m:
              m.side_effect = slow
              result = asyncio.run(adapter.retrieve(finding))
      - Creá el adapter fresco: ChromaKBAdapter(logger=None)
      - NO necesitás configurar _collection ni _model
      - Verificá: result == []
    """
    #adapter
    adapter = ChromaKBAdapter(logger=None)
    async def slow(*args, **kwargs):
        await asyncio.sleep(10)
    with patch.object(adapter, "_async_retrieve", new_callable=AsyncMock) as m:
        m.side_effect = slow
        result = asyncio.run(adapter.retrieve(finding, top_k=5))

    assert result == []
