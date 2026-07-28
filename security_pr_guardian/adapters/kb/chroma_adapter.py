"""ChromaKBAdapter — Implementación de KBRetrievalPort con ChromaDB + sentence-transformers.

Flujo:
1. En la primera ejecución, lee todos los .md de knowledge_base/, genera embeddings
   con all-MiniLM-L6-v2, y los persiste en ~/.security-guardian/kb/
2. En ejecuciones posteriores, carga la colección persistida directamente.
3. En cada query, convierte el CandidateFinding a texto de búsqueda,
   ejecuta similitud coseno, y retorna top-k KBFragments.

Reglas de negocio:
- Si todos los scores < 0.5 → marcar todos los fragmentos con baja_confianza=True
- Timeout de 5 segundos → retornar [] (lista vacía, sin parciales)
- Retornar como máximo top_k fragmentos (0 ≤ len(result) ≤ top_k)
- score_relevancia siempre en [0.0, 1.0]
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from security_pr_guardian.core.models import CandidateFinding, KBFragment
from security_pr_guardian.core.logger import StructuredLogger
from security_pr_guardian.ports.kb_retrieval import KBRetrievalPort


# Ruta donde se distribuye la KB dentro del paquete
KB_SOURCE_DIR = Path(__file__).resolve().parent.parent.parent / "knowledge_base"

# Ruta donde se persiste la colección ChromaDB
KB_PERSIST_DIR = Path.home() / ".security-guardian" / "kb"

# Modelo de embeddings (384 dims, rápido, buen balance calidad/velocidad)
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

# Nombre de la colección en ChromaDB
COLLECTION_NAME = "security_knowledge_base"

# Timeout para queries (segundos)
QUERY_TIMEOUT_SECONDS = 5


class ChromaKBAdapter(KBRetrievalPort):
    """Adaptador KB usando ChromaDB embebido + sentence-transformers.

    Implementa KBRetrievalPort con:
    - Indexación persistente en ~/.security-guardian/kb/
    - Embeddings con all-MiniLM-L6-v2
    - Similitud coseno para búsqueda semántica
    - Retorno top-k con score_relevancia normalizado a [0.0, 1.0]
    - Marcado de baja_confianza cuando todos los scores < 0.5
    - Timeout de 5s con retorno de [] y emisión de kb_timeout
    """

    def __init__(self, logger: Optional[StructuredLogger] = None):
        """Inicializa el adaptador ChromaDB.

        Args:
            logger: Logger estructurado para emitir eventos. Si es None,
                    el timeout no emitirá el evento kb_timeout (pero igualmente
                    retornará []).
        """
        self._logger = logger
        self._model = None  # SentenceTransformer, set in _ensure_initialized
        self._client = None  # chromadb.PersistentClient, set in _ensure_initialized
        self._collection = None  # chromadb.Collection, set in _ensure_initialized
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """Inicializa el modelo y la colección ChromaDB.

        Si la colección está vacía, indexa todos los .md de KB_SOURCE_DIR.
        Raises RuntimeError if chromadb or sentence_transformers are not installed.
        """
        if self._initialized:
            return

        # Lazy imports — deferred so module-level import never touches these
        # heavy packages. Tests can mock _ensure_initialized entirely.
        import chromadb as _chromadb_module  # noqa: PLC0415
        from sentence_transformers import SentenceTransformer as _SentenceTransformer  # noqa: PLC0415

        # Crear directorio de persistencia si no existe
        KB_PERSIST_DIR.mkdir(parents=True, exist_ok=True)

        # Cargar modelo de embeddings
        self._model = _SentenceTransformer(EMBEDDING_MODEL)

        # Inicializar cliente ChromaDB persistente con distancia coseno
        self._client = _chromadb_module.PersistentClient(path=str(KB_PERSIST_DIR))
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )

        # Si la colección está vacía, indexar la KB
        if self._collection.count() == 0:
            self._index_knowledge_base()

        self._initialized = True

    def _index_knowledge_base(self) -> None:
        """Lee todos los .md de KB_SOURCE_DIR y los indexa en ChromaDB.

        Recorre las subcarpetas:
        - cwes/
        - owasp_top10_2025/
        - historical_cases/
        - false_positives/

        Para cada archivo .md:
        1. Lee el contenido completo
        2. Usa el título (primera línea que empiece con #) como metadata 'titulo'
        3. Usa la ruta relativa como metadata 'fuente'
        4. Genera el embedding con self._model.encode()
        5. Lo añade a la colección con collection.add()

        Se encarga de la vectorizacion de los documentos a embeddings
        """
        #lista los archivos .md recursivamente en KB_SOURCE_DIR
        md_files = list(KB_SOURCE_DIR.rglob("*.md"))

        if not md_files: 
            return

        documents: list[str] = []
        embeddings: list[list[float]] = [] # lista de listas
        metadatas: list[dict] = [] #lista un diccionario por cada documento
        ids: list[str] = [] 

        for md_file in md_files:
            try:
                contenido = md_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                # Archivo ilegible — saltar
                continue

            if not contenido.strip():
                continue

            # Extraer título de la primera línea que empiece con #
            titulo = md_file.stem  # fallback: nombre del archivo sin extensión
            for line in contenido.splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    titulo = stripped.lstrip("#").strip()
                    break

            # Ruta relativa desde KB_SOURCE_DIR como fuente
            fuente = md_file.relative_to(KB_SOURCE_DIR).as_posix()

            # ID único: usar la ruta relativa
            doc_id = fuente.replace("/", "_").replace("\\", "_").replace(".md", "")

            # Generar embedding — convertir a float nativo para compatibilidad con ChromaDB
            embedding = [float(x) for x in self._model.encode(contenido)]

            documents.append(contenido)
            embeddings.append(embedding)
            metadatas.append({"titulo": titulo, "fuente": fuente})
            ids.append(doc_id)

        if documents:
            # Añadir al final para evitar reconstruirlo en cada insercion
            # El add es el metodo de chromadb para insertar documentos¿
            self._collection.add(
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas,
                ids=ids,
            )

    def _build_query_text(self, finding: CandidateFinding) -> str:
        """Construye el texto de búsqueda a partir de un CandidateFinding.

        Combina los campos más relevantes para la búsqueda semántica:
        - tipo_vulnerabilidad
        - cwe_id (si existe)
        - fragmento_codigo (primeros 200 chars)
        - patron_detectado

        Returns:
            String combinado para generar el embedding de la query.
        """
        # parts es una lista de strings que almacena partes del texto de busqueda
        parts: list[str] = []

        if finding.tipo_vulnerabilidad:
            parts.append(finding.tipo_vulnerabilidad)

        if finding.cwe_id:
            parts.append(finding.cwe_id)

        if finding.fragmento_codigo:
            parts.append(finding.fragmento_codigo[:200])

        if finding.patron_detectado:
            parts.append(finding.patron_detectado)

        return " ".join(parts)

    def _normalize_score(self, distance: float) -> float:
        """Convierte la distancia coseno de ChromaDB a score de relevancia [0.0, 1.0].

        ChromaDB con espacio "cosine" retorna distancias en [0, 2]:
        - 0 = idéntico (máxima similitud)
        - 2 = opuesto (mínima similitud)

        Score = 1 - (distance / 2) → mapea a [0.0, 1.0]

        Returns:
            Float en rango [0.0, 1.0] donde 1.0 = máxima relevancia.
        """
        score = 1.0 - (distance / 2.0)
        # Clampear a [0.0, 1.0] por seguridad ante valores fuera de rango
        return max(0.0, min(1.0, score))

    async def retrieve(self, finding: CandidateFinding, top_k: int = 3) -> list[KBFragment]:
        """Recupera fragmentos relevantes de la KB.

        Pasos:
        1. Construir texto de query con _build_query_text()
        2. Ejecutar la query ChromaDB con timeout de 5s
        3. Normalizar distances a scores con _normalize_score()
        4. Construir lista de KBFragment
        5. Si todos los scores < 0.5 → marcar baja_confianza=True en todos
        6. Retornar la lista (máximo top_k elementos)

        En caso de timeout (>5s) → retornar [] y loguear kb_timeout.
        """
        try:
            fragments = await asyncio.wait_for(
                self._async_retrieve(finding, top_k),
                timeout=QUERY_TIMEOUT_SECONDS,
            )
            return fragments
        except asyncio.TimeoutError:
            # Emitir evento kb_timeout si hay logger disponible
            if self._logger is not None:
                self._logger.log(
                    componente="KB_Retriever",
                    evento="kb_timeout",
                    timeout_seconds=QUERY_TIMEOUT_SECONDS,
                    finding_id=finding.finding_id,
                    tipo_vulnerabilidad=finding.tipo_vulnerabilidad,
                )
            return []

    async def _async_retrieve(self, finding: CandidateFinding, top_k: int) -> list[KBFragment]:
        """Lógica interna de recuperación, ejecutable con timeout.

        Toda la lógica de embeddings y ChromaDB se delega aquí para
        que asyncio.wait_for pueda cancelarla correctamente.
        """
        # Inicialización lazy — solo ocurre una vez
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._ensure_initialized)

        # Si la colección está vacía, retornar []
        if self._collection.count() == 0:
            return []

        # Construir texto de búsqueda
        query_text = self._build_query_text(finding)

        if not query_text.strip():
            return []

        # Generar embedding de la query en thread pool (CPU-bound)
        query_embedding = await loop.run_in_executor(
            None,
            lambda: [float(x) for x in self._model.encode(query_text)],
        )

        # Limitar top_k al número de documentos disponibles
        n_results = min(top_k, self._collection.count())
        if n_results == 0:
            return []

        # Ejecutar query ChromaDB en thread pool (I/O-bound)
        results = await loop.run_in_executor(
            None,
            lambda: self._collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
                include=["documents", "metadatas", "distances"],
            ),
        )

        # Extraer resultados (ChromaDB devuelve listas de listas)
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        if not documents:
            return []

        # Construir KBFragment por cada resultado
        fragments: list[KBFragment] = []
        for doc, meta, dist in zip(documents, metadatas, distances):
            score = self._normalize_score(dist)
            fragment = KBFragment(
                titulo=meta.get("titulo", ""),
                contenido=doc,
                fuente=meta.get("fuente", ""),
                score_relevancia=score,
                baja_confianza=False,  # se ajusta abajo si corresponde
            )
            fragments.append(fragment)

        # Aplicar regla de baja_confianza: si TODOS los scores < 0.5
        if fragments and all(f.score_relevancia < 0.5 for f in fragments):
            fragments = [f.model_copy(update={"baja_confianza": True}) for f in fragments]

        return fragments
