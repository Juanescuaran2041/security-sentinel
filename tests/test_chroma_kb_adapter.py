"""Tests unitarios para ChromaKBAdapter.

Casos a cubrir (Tarea 5.3):
  1. baja_confianza=True cuando TODOS los scores retornados son < 0.5.
  2. Retorno de lista vacía [] cuando el retrieve excede el timeout de 5s.
  3. Retorno de fragmentos disponibles (<3) con baja_confianza=True cuando
     todos sus scores son < 0.5 (KB con pocos documentos relevantes).
  4. score_relevancia siempre está dentro de [0.0, 1.0] para cualquier
     distancia que retorne ChromaDB.

Estrategia de mocking:
  - ChromaDB y sentence-transformers NO se instalan realmente.
  - Se mockea ChromaKBAdapter._ensure_initialized para saltear la inicialización.
  - Se mockea ChromaKBAdapter._collection con un MagicMock que simula
    los métodos count() y query().
  - Se mockea ChromaKBAdapter._model con un MagicMock que simula encode().
  - Para el timeout, se mockea _async_retrieve para que duerma más de 5s.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_pr_guardian.adapters.kb.chroma_adapter import ChromaKBAdapter
from security_pr_guardian.core.models import CandidateFinding, KBFragment, Severity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_finding() -> CandidateFinding:
    """CandidateFinding de ejemplo para usar en todos los tests."""
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


@pytest.fixture
def adapter() -> ChromaKBAdapter:
    """ChromaKBAdapter con inicialización mockeada para no tocar disco ni modelos."""
    kb = ChromaKBAdapter(logger=None)
    # Marcar como inicializado para que _ensure_initialized no intente
    # cargar chromadb/sentence-transformers reales
    kb._initialized = True
    kb._model = MagicMock()
    kb._collection = MagicMock()
    return kb


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_chroma_results(distances: list[float]) -> dict:
    """
    Construye un resultado falso con el formato que devuelve ChromaDB.
    Recibe una lista de distancias y genera documentos y metadatas ficticios
    del mismo largo.

    Recordá que ChromaDB devuelve listas de listas (una por query enviada).
    Acá siempre se envía 1 query, por eso todo está dentro de [0].

    Ejemplo con 2 resultados:
        {
            "documents": [["texto doc 0", "texto doc 1"]],
            "metadatas": [[{"titulo": "Doc 0", "fuente": "src/doc0.md"}, ...]],
            "distances": [[0.8, 1.2]],
        }
    """
    n = len(distances)
    return {
        "documents": [[f"contenido documento {i}" for i in range(n)]],
        "metadatas": [[{"titulo": f"Doc {i}", "fuente": f"src/doc{i}.md"} for i in range(n)]],
        "distances": [distances],
    }


# ---------------------------------------------------------------------------
# Test 1: baja_confianza=True cuando todos los scores < 0.5
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_baja_confianza_when_all_scores_below_threshold(adapter, sample_finding):
    """
    DADO: ChromaDB retorna 3 documentos con distancias que producen scores < 0.5.
    CUANDO: se llama a retrieve().
    ENTONCES: todos los KBFragment retornados tienen baja_confianza=True.

    Pistas:
      - score = 1 - (distance / 2), entonces para score < 0.5 necesitás distance > 1.0
      - Usá make_chroma_results([1.2, 1.5, 1.8]) para simular 3 resultados malos
      - Configurá adapter._collection.count.return_value = 3
      - Configurá adapter._collection.query.return_value = make_chroma_results(...)
      - Configurá adapter._model.encode.return_value = [0.1] * 384
      - Llamá a adapter.retrieve(sample_finding, top_k=3) y verificá baja_confianza
    """
    # TODO: Tu código aquí
    pass


# ---------------------------------------------------------------------------
# Test 2: lista vacía en timeout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_list_on_timeout(sample_finding):
    """
    DADO: _async_retrieve tarda más de 5 segundos (simulado con asyncio.sleep).
    CUANDO: se llama a retrieve().
    ENTONCES: el resultado es [] (lista vacía, sin resultados parciales).

    Pistas:
      - Creá un adapter fresco: ChromaKBAdapter(logger=None)
      - Usá patch.object(adapter, "_async_retrieve") para reemplazar _async_retrieve
        con un AsyncMock que haga: await asyncio.sleep(10)  ← más que el timeout
      - Llamá adapter.retrieve(sample_finding) y verificá que el resultado es []
      - No necesitás mockear _collection ni _model para este test
    """
    # TODO: Tu código aquí
    pass


# ---------------------------------------------------------------------------
# Test 3: menos de top_k fragmentos disponibles, todos con baja_confianza
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fewer_than_topk_fragments_with_baja_confianza(adapter, sample_finding):
    """
    DADO: la KB solo tiene 2 documentos, ambos con scores < 0.5.
    CUANDO: se llama a retrieve(top_k=3).
    ENTONCES:
      - Se retornan exactamente 2 fragmentos (no 3).
      - Ambos tienen baja_confianza=True.

    Pistas:
      - adapter._collection.count.return_value = 2
      - Usá make_chroma_results con 2 distancias > 1.0
      - Verificá len(result) == 2 y que ambos tienen baja_confianza=True
    """
    # TODO: Tu código aquí
    pass


# ---------------------------------------------------------------------------
# Test 4: score_relevancia siempre en [0.0, 1.0]
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_score_relevancia_within_bounds(adapter, sample_finding):
    """
    DADO: ChromaDB retorna documentos con distancias variadas (incluyendo
          valores extremos como 0.0 y 2.0).
    CUANDO: se llama a retrieve().
    ENTONCES: todos los score_relevancia están dentro de [0.0, 1.0].

    Pistas:
      - Usá make_chroma_results([0.0, 1.0, 2.0]) para cubrir los extremos
      - Verificá que todos los fragmentos tienen 0.0 <= f.score_relevancia <= 1.0
    """
    # TODO: Tu código aquí
    pass
