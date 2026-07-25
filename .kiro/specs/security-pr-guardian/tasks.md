# Implementation Plan: Security PR Guardian

## Overview

Security PR Guardian es una herramienta CLI pública (`pip install security-pr-guardian`) y GitHub Action que analiza Pull Requests combinando SAST (análisis estático con regex sobre 7 CWEs), escaneo de CVEs vía OSV.dev, RAG sobre una base de conocimiento OWASP/CWE (ChromaDB + sentence-transformers) y razonamiento LLM vía Amazon Bedrock para filtrar falsos positivos antes de publicar un comentario estructurado en el PR. El agente se adapta al equipo mediante un perfil de convenciones configurable (`.security-guardian.yml`) generado por el comando `security-guardian init --profile`.

El plan de implementación sigue la arquitectura hexagonal (Ports & Adapters) definida en el diseño. Se construye desde los cimientos (modelos y puertos) hacia afuera (adaptadores, orquestador, CLI), con tests unitarios, de integración y basados en propiedades (Hypothesis) entretejidos en cada tarea.

## Tasks

- [ ] 1. Estructura del proyecto y modelos de dominio
  - [x] 1.1 Inicializar la estructura de paquete Python (`pyproject.toml`, `setup.cfg`, `requirements.txt` con dependencias pinned)
  - [x] 1.2 Crear los modelos Pydantic en `security_pr_guardian/core/models.py` (`Severity`, `CandidateFinding`, `LLMVerdict`, `Recommendation`, `ConfirmedFinding`, `KBFragment`, `AnalysisResult`, `DependencyChange`, `LogEvent`, `AppConfig`)
  - [ ] 1.3 Definir los puertos (ABCs) en `security_pr_guardian/ports/` (`DiffExtractionPort`, `StaticAnalysisPort`, `CVELookupPort`, `KBRetrievalPort`, `LLMReasoningPort`, `PRCommentPort`)
  - [x] 1.4 Implementar `StructuredLogger` en `security_pr_guardian/core/logger.py` con emisión de eventos de log JSON con los campos `timestamp`, `analysis_id`, `componente`, `evento`, `duracion_ms` (opcional) y `detalle`
  - [ ] 1.5 Escribir tests unitarios para los modelos y para la validación de `AppConfig` (variables obligatorias ausentes, valores fuera de rango, merge env vars vs `config.yaml`)

- [ ] 2. Static_Analyzer — servidor MCP y adaptador
  - [ ] 2.1 Implementar `PatternEngine` en `security_pr_guardian/adapters/mcp/pattern_engine.py` con las 7 reglas regex (CWE-89, 78, 79, 502, 798, 327, 552) aplicadas sobre líneas con prefijo `+` del diff unificado
  - [ ] 2.2 Crear el servidor FastMCP `static_analyzer_server.py` que expone la herramienta `analyze_diff(diff: str) -> StaticAnalysisResult` usando `PatternEngine`; incluir manejo de `errores_parciales` por archivo; completar en máximo 60 s
  - [ ] 2.3 Implementar `StaticAnalyzerMCPAdapter` en `adapters/mcp/static_analyzer_adapter.py` implementando `StaticAnalysisPort`
  - [ ] 2.4 Crear fixtures de diff en `tests/fixtures/` para cada uno de los 7 CWE (`cwe_89_sql_injection.diff`, etc.) y para `clean_pr.diff` y `large_pr.diff` (>10 000 líneas)
  - [ ] 2.5 Escribir tests unitarios del `PatternEngine`: cada regla dispara en el fixture vulnerable y no genera falso positivo en `clean_pr.diff`
  - [ ] 2.6 Escribir test de contrato MCP para `analyze_diff`: input `{"diff": str}` → output coincide con el schema JSON de `StaticAnalysisResult`
  - [ ] 2.7 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 9: Detección de manifiestos exacta por nombre** — `st.sampled_from(MANIFEST_NAMES)` unión `st.text()` para verificar que solo los nombres canónicos se clasifican como manifiestos y los demás no
    - Validates: Requirements 2.2

- [ ] 3. CVE_Lookup — servidor MCP y adaptador
  - [ ] 3.1 Implementar el servidor FastMCP `cve_lookup_server.py` que expone `lookup_cve(package: str, version: str, ecosystem: str) -> list[CVEFinding] | ErrorFinding` llamando a `POST https://api.osv.dev/v1/querybatch`; reintentos: 2 intentos adicionales, espera fija de 3 s; `error_lookup` en fallo definitivo; `error_input` si `version` está vacía
  - [ ] 3.2 Implementar `CVELookupMCPAdapter` en `adapters/mcp/cve_lookup_adapter.py` implementando `CVELookupPort`; aplicar el límite de 50 dependencias (primeras 50 por orden de aparición); emitir finding `limit_exceeded` con conteo de omitidas cuando se supere el límite
  - [ ] 3.3 Escribir tests unitarios del adaptador CVE: `error_lookup` tras reintentos agotados (mockeado con `pytest-httpx`), `limit_exceeded` al pasar la dependencia 51, `error_input` cuando `version` está vacía, lista vacía cuando OSV no retorna vulnerabilidades
  - [ ] 3.4 Escribir test de contrato MCP para `lookup_cve`: input `{"package": str, "version": str, "ecosystem": str}` → output coincide con el schema de lista `CVEFinding`
  - [ ] 3.5 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 8: Límite de dependencias aplicado** — `st.integers(min_value=51, max_value=200)` como conteo de dependencias — verificar que se consultan exactamente las primeras 50 y que el resultado contiene un finding `limit_exceeded`
    - Validates: Requirements 4.6

- [ ] 4. DiffParser y detección de cambios en manifiestos
  - [ ] 4.1 Implementar `DiffParser` en `security_pr_guardian/core/diff_parser.py`: extracción de líneas `+` del diff unificado, detección del conjunto canónico de manifiestos (`package.json`, `requirements.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`, `Cargo.toml`, `Cargo.lock`, `go.mod`, `go.sum`, `pom.xml`, `build.gradle`, `vcpkg.json`, `package-lock.json`, `yarn.lock`), extracción de `DependencyChange`, truncación del diff a `max_diff_lines` con activación del flag `diff_truncated`
  - [ ] 4.2 Implementar `GitHubDiffAdapter` en `adapters/github/diff_adapter.py` implementando `DiffExtractionPort`: llamada a la API REST de GitHub para obtener el diff, reintentos con backoff exponencial (2 s, 4 s, 8 s), evento `analysis_failed` tras 3 reintentos agotados
  - [ ] 4.3 Escribir tests unitarios del `DiffParser`: detección correcta de manifiestos, extracción de dependencias modificadas, truncación a 10 000 líneas con `diff_truncated=True`, sin análisis CVE cuando no hay manifiestos
  - [ ] 4.4 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 5: Invariante de truncación de diff** — `st.integers(min_value=9990, max_value=15000)` como conteo de líneas — verificar que `diff_truncated=True` y que ningún `CandidateFinding.linea_inicio` referencia contenido más allá del límite de truncación
    - Validates: Requirements 2.6

- [ ] 5. KB_Retriever — ChromaKBAdapter y base de conocimiento
  - [x] 5.1 Crear la base de conocimiento en `security_pr_guardian/knowledge_base/`: 10 archivos Markdown para OWASP Top 10 2025 (`owasp_top10_2025/A01.md`–`A10.md`), 7 archivos de descripción + remediación de CWE (`cwes/CWE-89.md`, 78, 79, 502, 798, 327, 552), y al menos 20 casos históricos en `historical_cases/` (snippet vulnerable + snippet corregido + referencia CVE)
  - [x] 5.2 Implementar `ChromaKBAdapter` en `adapters/kb/chroma_adapter.py` implementando `KBRetrievalPort`: indexación en `~/.security-guardian/kb/` con `sentence-transformers/all-MiniLM-L6-v2`, similitud coseno, retorno de top-k con `score_relevancia`; `baja_confianza=True` cuando todos los scores < 0.5; timeout de 5 s con retorno de `[]` y emisión del evento `kb_timeout`
  - [ ] 5.3 Escribir tests unitarios del `ChromaKBAdapter`: `baja_confianza=True` cuando todos los scores < 0.5, retorno de lista vacía en timeout, retorno de fragmentos disponibles (<3) con `baja_confianza=True`, `score_relevancia` siempre en [0.0, 1.0]
  - [ ] 5.4 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 7: KB retorna como máximo top_k fragmentos** — `st.integers(min_value=1, max_value=10)` como `top_k` — verificar que `0 ≤ len(result) ≤ top_k`
    - Validates: Requirements 6.2, 6.7
  - [ ] 5.5 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 11: score_relevancia siempre en [0.0, 1.0]** — `st.builds(KBFragment, ...)` — verificar que `0.0 ≤ score_relevancia ≤ 1.0`
    - Validates: Requirements 6.3
  - [ ] 5.6 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 12: Fragmentos de baja confianza siempre marcados** — `st.lists(st.floats(min_value=0.0, max_value=0.499))` como lista de scores — verificar que cuando todos los scores < 0.5 cada fragmento tiene `baja_confianza=True`
    - Validates: Requirements 6.4
  - [ ] 5.7 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 13: Timeout de KB retorna lista vacía** — timeout mockeado, cualquier `CandidateFinding` como input — verificar que la lista retornada tiene longitud 0 y no contiene resultados parciales
    - Validates: Requirements 6.6

- [ ] 6. Adaptadores LLM — BedrockAdapter y AnthropicAdapter
  - [ ] 6.1 Implementar `BedrockAdapter` en `adapters/llm/bedrock_adapter.py` implementando `LLMReasoningPort`: Bedrock Converse API vía `boto3`, construcción del prompt (SYSTEM + USER) con `finding` y fragmentos KB formateados, parseo de `LLMVerdict` desde JSON, reintentos con backoff exponencial (5 s, 10 s, 20 s) en `ThrottlingException` y `ServiceUnavailableException`, marcado `no_evaluado` en fallo definitivo o JSON inválido
  - [ ] 6.2 Implementar `AnthropicAdapter` en `adapters/llm/anthropic_adapter.py` implementando `LLMReasoningPort`: misma estructura de prompt que `BedrockAdapter`, reintentos en `RateLimitError` y `APIConnectionError`, marcado `no_evaluado` en `AuthenticationError` o JSON inválido
  - [ ] 6.3 Escribir tests unitarios del `BedrockAdapter`: construcción correcta del prompt, reintento en `ThrottlingException` (mockeado vía `moto`), `no_evaluado` en fallo definitivo tras 3 reintentos, `no_evaluado` en JSON inválido, `no_evaluado` en campos requeridos faltantes en la respuesta
  - [ ] 6.4 Escribir tests unitarios del `AnthropicAdapter`: misma estructura de prompt que Bedrock, `no_evaluado` en JSON inválido, reintento en `RateLimitError`
  - [ ] 6.5 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 10: JSON inválido del LLM siempre produce no_evaluado** — `st.text()` unión `st.builds(dict, ...)` con campos aleatorios faltantes — verificar `disposition: "no_evaluado"` tanto para Bedrock como Anthropic
    - Validates: Requirements 5.8
  - [ ] 6.6 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 6: severidad_ajustada siempre es un valor válido del enum Severity** — `st.builds(ConfirmedFinding, ...)` desde respuesta LLM cruda — verificar que `severidad_ajustada` es exactamente uno de `critical`, `high`, `medium`, `low`, `info`
    - Validates: Requirements 5.4

- [ ] 7. PR_Commenter — GitHubPRCommenterAdapter y plantilla Jinja2
  - [ ] 7.1 Crear la plantilla Jinja2 `security_pr_guardian/templates/pr_comment.md.j2` con secciones obligatorias: (a) resumen ejecutivo con conteos por severidad, (b) tabla de hallazgos (`Severidad`, `Tipo`, `Archivo:Línea`, `CVE/CWE`), (c) detalle por hallazgo con fragmento de código en bloque Markdown, justificación y recomendación; pie con versión semver, modelo LLM y duración del análisis; marca de agua `<!-- security-pr-guardian -->`; bloque de advertencia si `diff_truncated=True`; mensaje de no-vulnerabilidades cuando no hay hallazgos confirmados (con conteos y timestamp ISO 8601 UTC)
  - [ ] 7.2 Implementar `GitHubPRCommenterAdapter` en `adapters/github/pr_commenter.py` implementando `PRCommentPort`: `POST` en primer comentario, detección de marca de agua `<!-- security-pr-guardian -->` para `PATCH` en comentario existente, reintentos con backoff exponencial (2 s, 4 s, 8 s), evento `comment_publish_failed` tras reintentos agotados
  - [ ] 7.3 Escribir tests unitarios del `GitHubPRCommenterAdapter`: POST en primer comentario, PATCH en subsiguiente (marca de agua detectada), reintento en 5xx (mockeado con `pytest-httpx`), evento `comment_publish_failed` tras reintentos agotados
  - [ ] 7.4 Escribir tests unitarios del renderizado de la plantilla: secciones obligatorias presentes, orden descendente de severidad en la tabla, mensaje de no-vulnerabilidades correcto, bloque de advertencia de truncación visible cuando `diff_truncated=True`

- [ ] 8. Security_Agent — orquestador central
  - [ ] 8.1 Implementar `SecurityAgent` en `security_pr_guardian/core/agent.py`: orquestación del pipeline completo (diff → SAST → CVE → KB → LLM → PR comment), generación del `analysis_id` UUID v4 y propagación a todos los componentes, ordenación de candidatos por severidad descendente y tope de 20 antes de invocar el LLM, manejo del flag dry-run (`--no-comment`), emisión de eventos de log estructurado en cada etapa del pipeline
  - [ ] 8.2 Escribir tests unitarios del `SecurityAgent`: análisis CVE omitido cuando no hay manifiestos en el diff, tope de 20 hallazgos respetado, `no_evaluado` propagado cuando el LLM falla, `disposition: "descartado"` aplicado a findings no explotables, dry-run omite la llamada a `PRCommentPort`
  - [ ] 8.3 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 1: Los hallazgos no explotables siempre se descartan** — `st.lists(st.builds(CandidateFinding, ...), min_size=0, max_size=30)` — verificar que todo finding con `es_explotable=False` tiene `disposition: "descartado"` y no aparece en `confirmed_findings`
    - Validates: Requirements 5.5
  - [ ] 8.4 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 2: analysis_id es UUID v4 válido en todos los eventos de log** — `st.builds(AppConfig, ...)` + ejecución de análisis mockeada — verificar que cada evento de log contiene `analysis_id` con formato UUID v4
    - Validates: Requirements 9.1, 9.2
  - [ ] 8.5 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 3: confirmed_findings siempre ordenados por severidad descendente** — `st.lists(st.builds(ConfirmedFinding, ...), min_size=0, max_size=25)` — verificar que no hay inversión de severidad entre elementos adyacentes
    - Validates: Requirements 7.1
  - [ ] 8.6 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 4: El número de hallazgos enviados al LLM nunca supera min(total_candidatos, 20)** — `st.integers(min_value=0, max_value=100)` como conteo de candidatos — verificar que las invocaciones a `LLMReasoningPort.evaluate_finding` nunca superan `min(len(candidates), 20)`
    - Validates: Requirements 5.6

- [ ] 9. Observabilidad — StructuredLogger y eventos de ciclo de vida
  - [ ] 9.1 Extender `StructuredLogger` con métodos de conveniencia para los eventos de ciclo de vida: `analysis_complete`, `analysis_failed`, `comment_publish_failed`, `diff_truncated`, `kb_timeout`, `llm_parse_failure` y eventos de finding (`finding_id`, `es_explotable`, `severidad_ajustada`, `justificacion`, `disposition`)
  - [ ] 9.2 Verificar que `duracion_ms` está presente si y solo si el evento representa una operación completada con inicio y fin medibles (ausente en eventos de solo-inicio)
  - [ ] 9.3 Escribir tests unitarios del logger: campos base requeridos en todo evento, `duracion_ms` presente solo cuando corresponde, evento `analysis_complete` con todos los conteos requeridos
  - [ ] 9.4 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 14: Los eventos de log siempre contienen los campos base requeridos** — `st.builds(LogEvent, ...)` con valores aleatorios — verificar que `timestamp`, `analysis_id`, `componente`, `evento` y `detalle` están siempre presentes
    - Validates: Requirements 9.2

- [ ] 10. CLI — comandos `check` e `init`
  - [ ] 10.1 Implementar `security_pr_guardian/cli/main.py` con `click` + `rich`: comando `security-guardian check --repo <owner/repo> --pr <number> [--output text|json] [--no-comment]` y comando `security-guardian init`
  - [ ] 10.2 Implementar la lógica de salida del CLI: salida con colores ANSI (verde en éxito, rojo/amarillo según severidad máxima), tabla de hallazgos con columnas `Severidad`, `Tipo`, `Archivo:Línea`, `CVE/CWE`, omisión de ANSI cuando `NO_COLOR` está presente o `TERM=dumb`
  - [ ] 10.3 Implementar el flag `--output json`: serialización completa de `AnalysisResult` a JSON en stdout sin salida ANSI
  - [ ] 10.4 Implementar el comando `security-guardian init`: generación de `.env.example` con todas las variables requeridas y sus descripciones, validación de credenciales del entorno con impresión del resultado por cada verificación
  - [ ] 10.5 Implementar la validación de configuración al arranque: mensaje estructurado en stderr con nombre exacto de la variable ausente, código de salida 2 antes de iniciar ninguna llamada a la API
  - [ ] 10.6 Escribir tests unitarios del CLI: código de salida 0 sin hallazgos explotables, código 1 con al menos un hallazgo explotable, código 2 en argumentos inválidos, código 2 en variable obligatoria ausente, `--output json` produce JSON parseable, `--no-comment` omite `PRCommentPort`, ANSI omitido con `NO_COLOR`
  - [ ] 10.7 Escribir test de propiedad (Hypothesis, `@settings(max_examples=100)`) — **Property 15: La salida JSON del CLI siempre es JSON parseable válido** — `st.builds(AnalysisResult, ...)` renderizado por el formateador CLI — verificar que los bytes en stdout se deserializan a JSON válido con las claves `analysis_id`, `confirmed_count`, `discarded_count`, `confirmed_findings` y `diff_truncated`
    - Validates: Requirements 1.8

- [ ] 14. Team Profile — perfil de equipo adaptable
  - [ ] 14.1 Crear el modelo Pydantic `TeamProfile` en `security_pr_guardian/core/models.py` con los campos: `frameworks` (list[str], default []), `auth_libraries` (list[str], default []), `allowed_patterns` (list[AllowedPattern], default []), `min_severity` (Severity, default LOW), `custom_exceptions` (list[str], default []) — y el modelo `AllowedPattern` con `cwe_id` (str) y `razon` (str)
  - [ ] 14.2 Implementar `TeamProfileLoader` en `security_pr_guardian/core/team_profile.py`: buscar `.security-guardian.yml` en cwd, parsear con `yaml.safe_load()`, validar con `TeamProfile`, retornar instancia con defaults en caso de archivo ausente o YAML inválido (sin lanzar excepciones), emitir warning al logger cuando el perfil falla
  - [ ] 14.3 Extender `BedrockAdapter` y `AnthropicAdapter` para aceptar `team_profile: TeamProfile | None` en `evaluate_finding` e inyectar la sección `## Perfil del Equipo` en el prompt USER cuando el perfil tiene contenido (frameworks, allowed_patterns, custom_exceptions no vacíos)
  - [ ] 14.4 Implementar `security-guardian init --profile` en el CLI: cuestionario interactivo con Rich prompts (frameworks, auth_libraries, allowed_patterns, min_severity, custom_exceptions), generación de `.security-guardian.yml`, confirmación antes de sobreescribir si el archivo ya existe
  - [ ] 14.5 Implementar el flag `--auto-detect` para `security-guardian init --profile`: escanear `requirements.txt`, `package.json`, `pyproject.toml`, `Cargo.toml` para detectar frameworks; detectar librerías de auth por presencia de nombres conocidos (`bcrypt`, `argon2`, `passlib`, `django-allauth`, `passport`, `jose`); inferir `min_severity` desde `.bandit` o `ruff.toml` si existen; usar valores detectados como defaults en el cuestionario
  - [ ] 14.6 Escribir tests unitarios del `TeamProfileLoader`: carga correcta desde YAML válido, degradación a defaults en YAML inválido, degradación a defaults cuando el archivo no existe, warning emitido en ambos casos de falla, ningún test lanza excepción no manejada
  - [ ] 14.7 Escribir tests unitarios del prompt con `TeamProfile`: sección `## Perfil del Equipo` presente en el prompt cuando el perfil tiene contenido, sección ausente cuando el perfil está vacío (todos defaults), `allowed_patterns` formateados correctamente en el prompt
  - [ ] 14.8 Escribir tests unitarios del auto-detect: detección correcta de frameworks desde fixtures de `requirements.txt` y `package.json`, detección de librerías de auth, no-crash cuando los archivos no existen

- [ ] 11. Tests de integración end-to-end
  - [ ] 11.1 Escribir test de integración — happy path completo: diff con inyección SQL + una dependencia vulnerable → finding confirmado en comentario del PR (todos los servicios externos mockeados con `pytest-httpx` y `moto`)
  - [ ] 11.2 Escribir test de integración — análisis CVE omitido cuando no hay manifiestos de dependencias en el diff
  - [ ] 11.3 Escribir test de integración — throttling de Bedrock: tras 3 reintentos, finding marcado `no_evaluado` con advertencia visible en comentario
  - [ ] 11.4 Escribir test de integración — truncación de diff: diff con más de 10 000 líneas → `diff_truncated=True`, advertencia en comentario, sin finding más allá de la línea 10 000
  - [ ] 11.5 Escribir test de integración — comentario PR existente: mock de GitHub retorna comentario con marca de agua → adaptador usa PATCH en lugar de POST
  - [ ] 11.6 Escribir test de integración — `llm_backend: anthropic`: pipeline completo con `AnthropicAdapter` activo (API mockeada)

- [ ] 12. Distribución, configuración y documentación
  - [ ] 12.1 Configurar `pyproject.toml` para distribución PyPI: nombre del paquete `security-pr-guardian`, entry point `security-guardian = security_pr_guardian.cli.main:cli`, dependencias pinned en `requirements.txt`
  - [ ] 12.2 Crear `action.yml` en la raíz para la GitHub Action: inputs (`repo`, `pr-number`, `github-token`, `bedrock-region`, `bedrock-model-id`), runs usando `python -m security_pr_guardian.cli.main check`
  - [ ] 12.3 Crear `.github/workflows/security-guardian.yml` con ejemplo de uso como step de CI/CD incluyendo configuración de secrets
  - [ ] 12.4 Completar el `README.md` con las secciones obligatorias: descripción y requisitos previos, instalación vía `pip install security-pr-guardian`, configuración de `GITHUB_TOKEN` y credenciales AWS, uso de `security-guardian check`, integración como GitHub Action con ejemplo de workflow YAML
  - [ ] 12.5 Crear `.env.example` con todas las variables de entorno requeridas y sus descripciones
  - [ ] 12.6 Crear plantillas de infraestructura como código en `infra/` (AWS CDK o CloudFormation) para despliegue en Lambda o ECS

- [ ] 13. Configuración de CI y cobertura
  - [ ] 13.1 Crear `.github/workflows/ci.yml` que ejecute `pytest --cov=security_pr_guardian --cov-fail-under=80` en cada PR, incluyendo las tres capas de tests con `moto` y `pytest-httpx`; ningún test corre contra infraestructura real
  - [ ] 13.2 Verificar que la cobertura cumple los umbrales: ≥ 80% en `security_pr_guardian/core/`, ≥ 80% en `security_pr_guardian/adapters/`, ≥ 70% en `security_pr_guardian/cli/`

## Task Dependency Graph

```json
{
  "waves": [
    { "wave": 1, "tasks": ["1"] },
    { "wave": 2, "tasks": ["2", "3", "4", "5", "6", "7", "14"] },
    { "wave": 3, "tasks": ["8", "9"] },
    { "wave": 4, "tasks": ["10"] },
    { "wave": 5, "tasks": ["11"] },
    { "wave": 6, "tasks": ["12", "13"] }
  ]
}
```

Las tareas 2–7 y 14 son independientes entre sí y pueden ejecutarse en paralelo una vez completada la tarea 1. La tarea 14.3 (extensión de los adapters LLM) tiene dependencia suave sobre 6.1 y 6.2, pero puede desarrollarse en paralelo si los adapters aún no están implementados — se integra cuando ambas tareas converjan.

## Notes

- **Team Profile**: `.security-guardian.yml` es opcional y versionable. Si no existe, el agente funciona con comportamiento por defecto. Si existe con YAML inválido, emite warning y continúa — nunca falla por el perfil.
- **Prioridad AWS**: Amazon Bedrock (`BedrockAdapter`) es el backend LLM principal y obligatorio para producción. `AnthropicAdapter` es solo un fallback para demos sin credenciales AWS.
- **No hay servidor persistente**: cada invocación de `security-guardian check` es stateless y autocontenida. No hay webhook, no hay servidor HTTP.
- **Regex sobre AST en el MVP**: el `PatternEngine` usa regex agnóstico del lenguaje sobre el texto del diff. La mejora a AST/tree-sitter queda como trabajo futuro.
- **KB local en el MVP**: `ChromaKBAdapter` es la única implementación de `KBRetrievalPort` en el MVP. `BedrockKBAdapter` (activable vía `kb_backend: bedrock`) queda como extensión futura.
- **Mocks en todos los tests**: ningún test corre contra infraestructura real. AWS se mockea vía `moto`, llamadas HTTP vía `pytest-httpx`.
- **PBT con Hypothesis**: los 15 tests de propiedad definidos en el diseño se implementan con `@settings(max_examples=100)` en la sección correspondiente de cada tarea.
- **Cobertura mínima**: ≥ 80% en `core/` y `adapters/`, ≥ 70% en `cli/`, aplicado en CI con `--cov-fail-under=80`.
