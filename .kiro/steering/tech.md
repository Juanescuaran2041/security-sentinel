---
inclusion: always
---

# Tech — Security PR Guardian

## Lenguaje y runtime

- Python 3.11+ en todo el pipeline. No mezclar lenguajes salvo que se
  justifique explícitamente en un design.md.
- Herramienta de línea de comandos (CLI), sin servidor persistente ni
  webhook. Cada ejecución es stateless y autocontenida.

## Librerías principales

- `click` + `rich` — CLI (comandos `check` e `init`, salida con colores
  y tablas legibles en terminal).
- `pygithub` o `httpx` directo a la API REST de GitHub — diff,
  manifiestos, publicación de comentarios.
- `httpx` (async) — cliente HTTP para OSV.dev y cualquier llamada
  externa; reintentos y control de timeout.
- `mcp` (SDK oficial, FastMCP) — los dos servidores MCP propios
  (`static_analyzer_server`, `cve_lookup_server`), transporte stdio.
- `chromadb` + `sentence-transformers` — vector store embebido para el
  RAG (KB_Retriever), sin servidor externo.
- `boto3` — cliente de Amazon Bedrock (Converse API) para el LLM.
- `pydantic` + `pydantic-settings` — modelos de dominio y `AppConfig`
  con validación condicional de credenciales según `llm_backend`.
- `pytest` + `pytest-asyncio` — testing. `moto` para mockear servicios
  AWS en tests, nunca contra cuenta real. `pytest-httpx` para mockear
  llamadas HTTP (GitHub, OSV.dev).
- `hypothesis` — property-based testing sobre los criterios EARS de
  `requirements.md`.

## Análisis estático — una sola estrategia, sin ambigüedad

- Reglas **regex** (`PatternEngine`) sobre las líneas `+` del diff
  unificado, agnósticas de lenguaje. No se usa `tree-sitter` ni el
  módulo `ast` de Python en el MVP — la mejora a AST queda documentada
  como trabajo futuro en `tasks.md`, no se mezclan ambos enfoques.
- Cubre 7 CWE objetivo: CWE-89, 78, 79, 502, 798, 327, 552 (ver tabla
  completa en `design.md`).

## Modelo de IA — Bedrock es obligatorio

- **Amazon Bedrock (Converse API) es el backend principal y
  obligatorio** — requisito no negociable del reto (Kiro + AWS). No se
  prioriza ninguna otra consideración de fricción de adopción sobre
  esto.
- La API directa de Anthropic queda disponible como **fallback
  opcional**, útil solo para desarrollo local sin gastar cuota de AWS
  mientras se construye. `llm_backend: bedrock` es el valor por
  defecto en `AppConfig`.
- No se usan modelos locales en este MVP.

## Infraestructura AWS

- **AWS SAM** para definir y desplegar cualquier función Lambda —
  sintaxis simplificada sobre CloudFormation, evita CDK a menos que el
  equipo ya lo domine.
- **IAM de mínimo privilegio siempre**: nunca `Action: "*"` ni
  `Resource: "*"`. Permiso específico por recurso. Nunca usar
  credenciales root para que el agente/Kiro interactúe con AWS.
- Credenciales nunca hardcodeadas: variables de entorno o Secrets
  Manager/SSM Parameter Store.
- Observabilidad obligatoria si hay Lambdas: dashboard de CloudWatch con
  invocaciones, errores y latencia — no es opcional, es parte de
  "hecho".

## MCP

- Dos servidores MCP propios (`static_analyzer_server`,
  `cve_lookup_server`) exponen el analizador estático y el cliente OSV
  como tools estándar vía `@mcp.tool()`.
- MCP oficiales de AWS disponibles vía `awslabs/mcp`: AWS Documentation
  MCP Server (evita alucinar parámetros de boto3/SAM) — Bedrock
  Knowledge Base MCP Server queda como extensión futura (el MVP usa
  ChromaDB local, no Bedrock KB).
- Configurar el `command` del servidor como `uvx` (binario) o `docker`
  según lo que el servidor requiera; revisar disponibilidad del profile
  de AWS antes de asumir credenciales activas.

## Testing y validación

- Arquitectura hexagonal: los adaptadores reales se prueban con mocks
  (`moto`, `pytest-httpx`); el `SecurityAgent` se prueba primero con
  fakes en memoria antes de conectar cualquier adaptador real.
- Cada criterio EARS de `requirements.md` debe mapear a al menos un
  test. Property-based tests para las invariantes que
  sostienen la demo — ver `tasks.md` para la lista priorizada.

