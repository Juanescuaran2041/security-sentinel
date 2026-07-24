# Requirements Document

## Introduction

**Security PR Guardian** es una herramienta CLI de seguridad que el desarrollador ejecuta manualmente o integra como step en un pipeline de GitHub Actions/CI. Combina análisis estático de código, verificación de CVEs en dependencias y razonamiento contextual mediante un LLM (vía Amazon Bedrock) para identificar vulnerabilidades realmente explotables, reduciendo el ruido de los falsos positivos característicos de las herramientas de seguridad tradicionales.

El agente expone al menos un servidor MCP propio (para análisis estático y/o consulta de CVEs), utiliza RAG sobre una base de conocimiento de patrones de vulnerabilidad (CWE/OWASP Top 10) y publica un comentario estructurado directamente en el PR con los hallazgos priorizados por severidad y explicados en lenguaje natural.

El sistema está diseñado para distribución pública: cualquier desarrollador u organización puede instalarlo con `pip install security-pr-guardian` y usarlo como comando CLI o como GitHub Action publicada en el GitHub Marketplace.

---

## Glossary

- **PR (Pull Request)**: Solicitud de incorporación de cambios en un repositorio de GitHub.
- **Diff**: Conjunto de líneas añadidas y eliminadas entre la rama base y la rama de origen de un PR, representado en formato unified diff.
- **Manifiesto de dependencias**: Archivo que declara las dependencias de un proyecto (ej. `package.json`, `requirements.txt`, `Cargo.toml`, `vcpkg.json`).
- **CVE (Common Vulnerabilities and Exposures)**: Identificador estándar para vulnerabilidades de seguridad conocidas.
- **OSV (Open Source Vulnerabilities)**: Base de datos pública de vulnerabilidades en paquetes de código abierto, accesible en `osv.dev`.
- **SAST (Static Application Security Testing)**: Análisis estático del código fuente en busca de patrones de vulnerabilidad sin ejecutar el programa.
- **CWE (Common Weakness Enumeration)**: Clasificación de debilidades de software mantenida por MITRE. Los identificadores siguen el formato `CWE-<número>` (ej. `CWE-89`).
- **OWASP Top 10**: Lista de las diez categorías de riesgo de seguridad web más críticas publicada por OWASP (versión 2021).
- **RAG (Retrieval-Augmented Generation)**: Técnica que enriquece el contexto de un LLM recuperando fragmentos relevantes de una base de conocimiento antes de generar una respuesta.
- **MCP (Model Context Protocol)**: Protocolo estándar para exponer herramientas y recursos a agentes LLM.
- **CLI (Command Line Interface)**: Interfaz de línea de comandos mediante la cual el usuario invoca el agente.
- **GitHub Actions**: Plataforma de CI/CD de GitHub donde el agente puede ejecutarse automáticamente como step en el pipeline al abrirse un PR.
- **Agente LLM**: Componente que recibe resultados de herramientas y razona sobre ellos usando un modelo de lenguaje grande.
- **Bedrock_Client**: Componente que gestiona la comunicación con Amazon Bedrock para invocar modelos de lenguaje.
- **Static_Analyzer**: Componente MCP que ejecuta el análisis estático sobre el diff del PR.
- **CVE_Lookup**: Componente MCP que consulta OSV.dev para verificar vulnerabilidades en dependencias.
- **KB_Retriever**: Componente que recupera patrones de vulnerabilidad relevantes desde la base de conocimiento vectorial (RAG).
- **PR_Commenter**: Componente que publica el comentario de resultados en el PR de GitHub.
- **Security_Agent**: Orquestador central que coordina todos los componentes y toma decisiones mediante razonamiento LLM.
- **Finding**: Hallazgo de seguridad candidato producido por el análisis estático o la verificación de CVEs.
- **Severidad**: Nivel de criticidad de un hallazgo. Valores válidos: `critical`, `high`, `medium`, `low`, `info`.
- **Ecosistema**: Nombre del gestor de paquetes al que pertenece una dependencia (ej. `PyPI`, `npm`, `crates.io`, `Go`, `Maven`). Debe ser proporcionado explícitamente por el llamador al invocar CVE_Lookup.
- **Hexagonal Architecture (Ports & Adapters)**: Estilo arquitectónico que aísla la lógica de negocio del núcleo de los detalles técnicos externos mediante puertos (interfaces) y adaptadores (implementaciones intercambiables).
- **Port**: Interfaz abstracta del núcleo de la arquitectura hexagonal que define un contrato de entrada o salida sin acoplarse a ninguna tecnología concreta.
- **Adapter**: Implementación concreta de un Port que conecta el núcleo con un sistema externo específico (GitHub, OSV.dev, Amazon Bedrock, MCP). Los adaptadores son intercambiables.

---

## Requirements

### Requisito 1: Interfaz de terminal y modos de ejecución

**User Story:** Como desarrollador o ingeniero de CI/CD, quiero invocar el agente mediante un comando CLI para analizar un PR concreto, integrar el análisis en pipelines de GitHub Actions y configurar el entorno inicial, para adaptar el uso a distintos flujos de trabajo sin necesidad de un servidor HTTP persistente.

#### Criterios de Aceptación

1. THE Security_Agent SHALL exponer el comando principal `security-guardian check --repo <owner/repo> --pr <number>` que inicia el análisis de un PR concreto; la autenticación con GitHub se realizará exclusivamente mediante la variable de entorno `GITHUB_TOKEN`.
2. WHEN se ejecuta `security-guardian check`, THE Security_Agent SHALL utilizar los mismos componentes internos (Static_Analyzer, CVE_Lookup, KB_Retriever, Bedrock_Client, PR_Commenter) sin duplicar lógica de análisis.
3. WHEN `security-guardian check` completa el análisis sin encontrar vulnerabilidades explotables, THE Security_Agent SHALL imprimir en la salida estándar un resumen con colores ANSI (verde para éxito) y terminar con código de salida 0.
4. WHEN `security-guardian check` completa el análisis y encuentra al menos una vulnerabilidad explotable, THE Security_Agent SHALL imprimir en la salida estándar un resumen con colores ANSI (rojo o amarillo según severidad máxima), una tabla de hallazgos con columnas `Severidad`, `Tipo`, `Archivo:Línea` y `CVE/CWE`, y terminar con código de salida 1.
5. IF `security-guardian check` recibe argumentos inválidos o le faltan los parámetros obligatorios `--repo` o `--pr`, THEN THE Security_Agent SHALL imprimir un mensaje de error descriptivo en la salida de error estándar y terminar con código de salida 2.
6. IF `security-guardian check` encuentra un error de configuración (variable de entorno obligatoria ausente o credencial inválida), THEN THE Security_Agent SHALL imprimir un mensaje de error descriptivo en la salida de error estándar y terminar con código de salida 2.
7. WHERE el entorno no soporte secuencias de escape ANSI (variable de entorno `NO_COLOR` presente o `TERM=dumb`), THE Security_Agent SHALL omitir los códigos de color ANSI en toda la salida del CLI.
8. WHEN se ejecuta `security-guardian check` con el flag `--output json`, THE Security_Agent SHALL emitir la salida completa del análisis en formato JSON a la salida estándar en lugar del formato de terminal con colores ANSI, manteniendo los mismos códigos de salida (0, 1, 2).
9. WHEN se ejecuta `security-guardian check` con el flag `--no-comment`, THE Security_Agent SHALL completar el análisis completo pero omitir la publicación del comentario en el PR (modo dry-run), manteniendo los mismos códigos de salida y salida de terminal.
10. THE Security_Agent SHALL exponer el comando `security-guardian init` que genere un archivo `.env.example` con todas las variables de entorno requeridas y sus descripciones, y valide las credenciales configuradas en el entorno actual imprimiendo el resultado de cada verificación.
11. WHEN el mismo comando `security-guardian check` se ejecuta como step en un workflow de GitHub Actions, THE Security_Agent SHALL funcionar sin modificaciones adicionales; THE Security_Agent SHALL incluir en el repositorio un archivo de ejemplo `.github/workflows/security-guardian.yml` que demuestre su uso como step de CI/CD.

---

### Requisito 2: Extracción del diff y detección de cambios en dependencias

**User Story:** Como agente de seguridad, quiero extraer el diff del PR e identificar si hay cambios en manifiestos de dependencias, para enfocar el análisis CVE únicamente en las dependencias modificadas.

#### Criterios de Aceptación

1. WHEN el usuario ejecuta `security-guardian check --repo <owner/repo> --pr <number>`, THE Security_Agent SHALL extraer el diff completo del PR en formato unified diff usando la API de GitHub con autenticación mediante la variable de entorno `GITHUB_TOKEN`.
2. THE Security_Agent SHALL identificar como manifiestos de dependencias los archivos cuyo nombre coincida exactamente con alguno de los siguientes: `package.json`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, `Cargo.toml`, `Cargo.lock`, `vcpkg.json`, `go.mod`, `go.sum`, `pom.xml`, `build.gradle`.
3. WHEN el diff contiene cambios en al menos un manifiesto de dependencias, THE Security_Agent SHALL extraer la lista de dependencias añadidas o con versión modificada (líneas con prefijo `+` que no sean líneas de contexto) para su análisis CVE.
4. WHEN el diff no contiene cambios en ningún manifiesto de dependencias, THE Security_Agent SHALL omitir el análisis CVE y continuar únicamente con el análisis estático.
5. IF la API de GitHub retorna un código de error HTTP (4xx o 5xx) al extraer el diff, THEN THE Security_Agent SHALL reintentar la solicitud hasta 3 veces con retroceso exponencial de 2 segundos base (2s, 4s, 8s) antes de marcar el análisis como fallido con evento `analysis_failed`.
6. THE Security_Agent SHALL procesar diffs de hasta 10.000 líneas modificadas; WHEN el diff supere ese límite, THE Security_Agent SHALL analizar únicamente los primeros 10.000 cambios y añadir una advertencia visible al comentario del PR indicando que el diff fue truncado.

---

### Requisito 3: Análisis estático de código mediante servidor MCP

**User Story:** Como equipo de desarrollo, quiero que el agente analice el código modificado en busca de patrones de vulnerabilidad conocidos, para detectar problemas de seguridad introducidos en el PR.

#### Criterios de Aceptación

1. THE Static_Analyzer SHALL exponer sus capacidades de análisis como herramientas MCP accesibles por el Security_Agent mediante el protocolo MCP estándar.
2. WHEN el Security_Agent invoca la herramienta MCP de análisis estático, THE Static_Analyzer SHALL recibir el diff en formato unified diff y analizar las líneas añadidas (prefijo `+`) en busca de los siguientes patrones: inyección SQL (CWE-89), inyección de comandos OS (CWE-78), Cross-Site Scripting (CWE-79), deserialización insegura (CWE-502), secretos y credenciales hardcodeadas (CWE-798), uso de algoritmos criptográficos débiles MD5/SHA1/DES (CWE-327), y referencias a rutas absolutas con datos sensibles (CWE-552).
3. WHEN el Static_Analyzer detecta un patrón de vulnerabilidad, THE Static_Analyzer SHALL retornar un Finding con los campos: `tipo_vulnerabilidad` (string), `archivo` (string), `linea_inicio` (integer, número de línea en el archivo destino), `linea_fin` (integer, igual a `linea_inicio` para vulnerabilidades de una sola línea), `fragmento_codigo` (string, máximo 500 caracteres), `patron_detectado` (string), `cwe_id` (string en formato `CWE-<número>`, ej. `CWE-89`).
4. WHEN el Static_Analyzer no detecta ningún patrón de vulnerabilidad en el diff, THE Static_Analyzer SHALL retornar una lista vacía de Findings.
5. IF el Static_Analyzer encuentra un error al procesar un archivo específico del diff, THEN THE Static_Analyzer SHALL registrar el error internamente, continuar con el análisis de los archivos restantes, e incluir en el resultado un objeto `{ "archivo": "<nombre>", "error": "<descripción del error>" }` en el campo `errores_parciales` de la respuesta.
6. THE Static_Analyzer SHALL completar el análisis de un diff de hasta 10.000 líneas en un plazo máximo de 60 segundos, medido desde la recepción de la invocación MCP hasta el retorno de la respuesta MCP.

---

### Requisito 4: Verificación de CVEs en dependencias mediante servidor MCP

**User Story:** Como equipo de desarrollo, quiero que el agente verifique si las dependencias nuevas o modificadas tienen CVEs conocidos, para detectar el riesgo de introducir paquetes vulnerables.

#### Criterios de Aceptación

1. THE CVE_Lookup SHALL exponer la consulta de vulnerabilidades como herramienta MCP accesible por el Security_Agent mediante el protocolo MCP estándar.
2. WHEN el Security_Agent invoca la herramienta MCP de consulta CVE con una dependencia, su versión y su ecosistema (campos obligatorios), THE CVE_Lookup SHALL consultar la API REST de OSV.dev (`https://api.osv.dev/v1/query`) con esos tres valores. IF la versión está ausente o es vacía, THEN THE CVE_Lookup SHALL retornar un Finding de tipo `error_input` indicando que la versión es obligatoria.
3. WHEN OSV.dev retorna vulnerabilidades para una dependencia, THE CVE_Lookup SHALL retornar un Finding por cada vulnerabilidad con los campos: `cve_id` (string), `paquete` (string), `version` (string), `ecosistema` (string), `severidad` (string, uno de: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` según CVSS/OSV), `descripcion` (string), `referencias` (lista de strings).
4. WHEN OSV.dev no retorna vulnerabilidades para una dependencia, THE CVE_Lookup SHALL retornar una lista vacía para esa dependencia.
5. IF la API de OSV.dev retorna un código de error HTTP o no responde en 10 segundos, THEN THE CVE_Lookup SHALL reintentar la solicitud hasta 2 veces con espera de 3 segundos entre intentos; IF el fallo persiste tras todos los reintentos, THEN THE CVE_Lookup SHALL retornar un Finding de tipo `error_lookup` con los campos `paquete`, `version`, `ecosistema` y `error_descripcion`.
6. THE CVE_Lookup SHALL procesar consultas para hasta 50 dependencias distintas en una misma ejecución; WHEN el número de dependencias supere 50, THE CVE_Lookup SHALL retornar un Finding de tipo `limit_exceeded` que indique cuántas dependencias fueron omitidas, y analizar únicamente las primeras 50 por orden de aparición en el diff.

---

### Requisito 5: Razonamiento contextual del agente LLM para reducción de falsos positivos

**User Story:** Como equipo de desarrollo, quiero que el agente LLM razone sobre cada hallazgo candidato en el contexto real del código, para que solo se reporten las vulnerabilidades realmente explotables y se reduzca el ruido.

#### Criterios de Aceptación

1. WHEN el Security_Agent recibe los Findings del Static_Analyzer y del CVE_Lookup, THE Security_Agent SHALL invocar al Bedrock_Client con los Findings, el fragmento de código contextual relevante y el contexto RAG recuperado por el KB_Retriever.
2. THE Bedrock_Client SHALL invocar un modelo de Amazon Bedrock usando la API de Amazon Bedrock con autenticación mediante credenciales AWS IAM.
3. WHEN el Bedrock_Client envía los Findings al modelo, THE Bedrock_Client SHALL estructurar el prompt incluyendo: el fragmento de código, el tipo de vulnerabilidad, el CWE/CVE asociado, el contexto RAG y la instrucción de evaluar si la vulnerabilidad es explotable en ese contexto específico.
4. WHEN el modelo LLM evalúa un Finding, THE Security_Agent SHALL obtener como respuesta estructurada (JSON parseable): `es_explotable` (boolean), `severidad_ajustada` (string: `critical`/`high`/`medium`/`low`/`info`), `justificacion` (string, mínimo 50 palabras), `recomendacion` (objeto JSON con los subcampos: `descripcion` (string no vacío describiendo la corrección), `codigo_corregido` (string con un snippet de código en el lenguaje del archivo afectado que muestre la versión corregida, o cadena vacía si no aplica), y `referencia` (string con URL o identificador de CWE o OWASP relevante, ej. `"CWE-89"` o `"https://owasp.org/Top10/A03_2021-Injection/"`)).
5. IF `es_explotable` es `false` para un Finding, THEN THE Security_Agent SHALL excluir ese Finding del comentario final del PR y registrarlo en el log interno como falso positivo descartado con el campo `disposition: "descartado"`.
6. WHEN el número de Findings supere 20, THE Security_Agent SHALL procesar los primeros 20 ordenados por severidad descendente y añadir una nota al comentario del PR indicando que se alcanzó el límite de análisis.
7. IF el Bedrock_Client recibe un error de la API de Bedrock (throttling, timeout, error de servicio), THEN THE Security_Agent SHALL reintentar la invocación hasta 3 veces con retroceso exponencial de base 5 segundos; IF el fallo persiste, THEN THE Security_Agent SHALL marcar ese Finding con estado `no_evaluado` e incluirlo en el comentario del PR con una etiqueta de advertencia visible indicando que no pudo ser evaluado.
8. IF la respuesta del modelo LLM no es un JSON válido o no contiene los campos requeridos (`es_explotable`, `severidad_ajustada`, `justificacion`, `recomendacion`), THEN THE Security_Agent SHALL marcar ese Finding con estado `no_evaluado` e incluirlo en el comentario del PR con una etiqueta de advertencia visible indicando fallo de parseo.

---

### Requisito 6: Enriquecimiento mediante RAG sobre base de conocimiento de vulnerabilidades

**User Story:** Como agente de seguridad, quiero recuperar patrones de vulnerabilidad relevantes desde una base de conocimiento indexada antes de razonar sobre cada hallazgo, para que el LLM disponga de contexto experto adicional que mejore la precisión del veredicto.

#### Criterios de Aceptación

1. THE KB_Retriever SHALL indexar una base de conocimiento que incluya al menos: las 10 categorías del OWASP Top 10 (versión 2025), las descripciones de los CWEs asociados a los patrones de vulnerabilidad que el Static_Analyzer es capaz de detectar, y al menos 20 casos históricos de vulnerabilidades reales con su patrón de código vulnerable y su solución documentada.
2. WHEN el Security_Agent prepara el razonamiento sobre un Finding, THE KB_Retriever SHALL recuperar los 3 fragmentos más relevantes de la base de conocimiento usando similitud semántica entre el Finding y los documentos indexados.
3. THE KB_Retriever SHALL retornar cada fragmento recuperado con los campos: `titulo` (string), `contenido` (string), `fuente` (string), `score_relevancia` (float entre 0.0 y 1.0).
4. IF el score_relevancia de todos los fragmentos recuperados es inferior a 0.5, THEN THE KB_Retriever SHALL retornar los 3 fragmentos de mayor score de todas formas, añadiendo el campo `baja_confianza: true` en cada fragmento para que el Security_Agent lo considere al construir el prompt.
5. THE KB_Retriever SHALL completar la recuperación de contexto para un Finding en un plazo máximo de 5 segundos, medido desde la recepción de la solicitud de recuperación hasta el retorno de la respuesta.
6. IF el KB_Retriever no completa la recuperación en 5 segundos, THEN THE KB_Retriever SHALL retornar una respuesta de error con el campo `error: "timeout"` y cero fragmentos, sin retornar resultados parciales.
7. IF la base de conocimiento contiene menos de 3 fragmentos relevantes para un Finding dado, THEN THE KB_Retriever SHALL retornar únicamente los fragmentos disponibles (entre 0 y 2) con el campo `baja_confianza: true` en cada uno.
8. WHERE se configure el uso de Amazon Bedrock Knowledge Bases (bedrock-kb-retrieval-mcp-server), THE KB_Retriever SHALL utilizar dicho servicio como backend de indexación y recuperación vectorial en lugar de una solución local.

---

### Requisito 7: Publicación de comentario estructurado en el Pull Request

**User Story:** Como desarrollador que abre un PR, quiero recibir un comentario claro y accionable con los hallazgos de seguridad priorizados, para poder entender y resolver los problemas sin necesidad de interpretar logs técnicos.

#### Criterios de Aceptación

1. WHEN el Security_Agent completa el razonamiento sobre todos los Findings, THE PR_Commenter SHALL publicar un único comentario en el PR usando la API de GitHub con los hallazgos confirmados (`es_explotable: true`), ordenados de mayor a menor severidad (`critical` > `high` > `medium` > `low` > `info`).
2. THE PR_Commenter SHALL estructurar el comentario en formato Markdown con las siguientes secciones obligatorias: (a) resumen ejecutivo con el número de hallazgos por cada nivel de severidad, (b) tabla de hallazgos con columnas `Severidad`, `Tipo`, `Archivo:Línea`, `CVE/CWE`, y (c) una sección de detalle por cada hallazgo que incluya el fragmento de código en bloque de código Markdown, la justificación del agente y la recomendación de corrección.
3. WHEN no existen Findings con `es_explotable: true`, THE PR_Commenter SHALL publicar un comentario Markdown indicando que no se detectaron vulnerabilidades explotables, el número total de hallazgos candidatos evaluados, el número descartados como falsos positivos y la fecha/hora del análisis en formato ISO 8601 UTC.
4. WHEN el Security_Agent ya publicó un comentario en una ejecución anterior para el mismo PR (identificado por el número de PR y el `repository.full_name`), THE PR_Commenter SHALL editar el comentario existente usando su ID almacenado, en lugar de crear un comentario nuevo.
5. IF la API de GitHub retorna un error HTTP al publicar o editar el comentario, THEN THE PR_Commenter SHALL reintentar hasta 3 veces con retroceso exponencial de base 2 segundos (2s, 4s, 8s); IF todos los reintentos fallan, THEN THE PR_Commenter SHALL registrar un evento `comment_publish_failed` en el log con el `analysis_id`, el código de error HTTP y el número de intentos realizados.
6. THE PR_Commenter SHALL incluir al pie de cada comentario publicado: la versión del Security PR Guardian (semver), el identificador del modelo LLM utilizado y la duración total del análisis en segundos con un decimal de precisión.

---

### Requisito 8: Distribución pública y configuración

**User Story:** Como cualquier desarrollador u organización, quiero instalar Security PR Guardian con un solo comando y configurarlo con mis credenciales, para beneficiarme del análisis de seguridad automatizado en mis PRs sin necesidad de desplegar un servidor.

#### Criterios de Aceptación

1. THE Security_Agent SHALL leer su configuración desde la variable de entorno `GITHUB_TOKEN` (obligatoria) y, opcionalmente, desde un archivo `config.yaml` en la raíz del proyecto; las variables de entorno tienen precedencia sobre los valores del archivo. Las variables de entorno obligatorias son: `GITHUB_TOKEN` (token de acceso personal para la API de GitHub), `BEDROCK_REGION` (región AWS de Bedrock), `BEDROCK_MODEL_ID` (identificador del modelo LLM). El archivo `config.yaml` opcional puede incluir los campos: `bedrock_region` (string), `bedrock_model_id` (string), `kb_backend` (string, valor exactamente `local` o `bedrock`, default: `local`), `osv_timeout_seconds` (integer, 1–300, default: 10), `max_diff_lines` (integer, 1–10000, default: 10000), `max_dependencies` (integer, 1–1000, default: 50).
2. THE Security_Agent SHALL validar la presencia de todas las variables de entorno obligatorias al arrancar; IF falta alguna variable obligatoria, THEN THE Security_Agent SHALL imprimir en la salida de error estándar un mensaje estructurado que indique exactamente el nombre de la variable ausente y terminar con código de salida 2.
3. THE Security_Agent SHALL estar disponible como paquete Python instalable mediante `pip install security-pr-guardian`, publicado en PyPI con las dependencias pinned en el archivo `requirements.txt` del proyecto.
4. THE Security_Agent SHALL estar disponible como GitHub Action publicada en el GitHub Marketplace, de forma que cualquier repositorio pueda añadir el step `uses: <org>/security-pr-guardian@v<version>` en su workflow sin instalar nada manualmente.
5. THE Security_Agent SHALL incluir en el repositorio del proyecto un archivo `README.md` con las siguientes secciones: (a) descripción del proyecto y requisitos previos, (b) instalación vía `pip install security-pr-guardian`, (c) configuración de la variable de entorno `GITHUB_TOKEN` y credenciales AWS, (d) uso del comando CLI `security-guardian check`, y (e) integración como GitHub Action con ejemplo de workflow YAML.
6. THE Security_Agent SHALL incluir en el repositorio un archivo de ejemplo `.github/workflows/security-guardian.yml` que demuestre su uso como step en un pipeline de CI/CD de GitHub Actions, incluyendo la configuración de los secrets necesarios.
7. WHERE se despliegue el agente en AWS (Lambda o ECS), THE Security_Agent SHALL incluir plantillas de infraestructura como código (AWS CDK o CloudFormation) para facilitar el despliegue por parte de terceros.

---

### Requisito 10: Perfil de equipo y adaptación contextual del análisis

**User Story:** Como desarrollador o líder técnico, quiero configurar las prácticas y convenciones de seguridad específicas de mi equipo mediante un comando interactivo, para que el agente adapte su razonamiento a nuestro contexto en lugar de aplicar reglas genéricas que generen falsos positivos irrelevantes.

#### Criterios de Aceptación

1. THE Security_Agent SHALL exponer el subcomando `security-guardian init --profile` que inicia un cuestionario interactivo en la terminal (usando Rich prompts) con las siguientes preguntas: (a) frameworks y lenguajes principales del proyecto, (b) librería de autenticación/hashing usada, (c) usos legítimos de patrones habitualmente marcados como vulnerables (ej. `pickle` en caché interno, `md5` para ETags), (d) severidad mínima a reportar, y (e) excepciones o convenciones de seguridad propias del equipo.

2. WHEN el usuario completa el cuestionario de `security-guardian init --profile`, THE Security_Agent SHALL generar un archivo `.security-guardian.yml` en la raíz del repositorio con los campos: `team_profile.frameworks` (lista de strings), `team_profile.auth_libraries` (lista de strings), `team_profile.allowed_patterns` (lista de objetos `{cwe_id, razon}`), `team_profile.min_severity` (string: `critical`/`high`/`medium`/`low`/`info`, default `low`), y `team_profile.custom_exceptions` (lista de strings de texto libre).

3. WHEN el archivo `.security-guardian.yml` existe en la raíz del repositorio al ejecutar `security-guardian check`, THE Security_Agent SHALL leer el `team_profile` y pasarlo al `LLMReasoningPort` como contexto adicional en el prompt de evaluación de cada finding, anteponiéndolo al contexto RAG estándar.

4. WHEN el `team_profile` declara un patrón como permitido (`allowed_patterns`) con el mismo `cwe_id` que un finding, THE Security_Agent SHALL incluir esa excepción en el prompt del LLM para que considere explícitamente si el hallazgo cae dentro del uso permitido antes de emitir su veredicto.

5. IF el archivo `.security-guardian.yml` existe pero contiene YAML inválido o campos con tipos incorrectos, THEN THE Security_Agent SHALL emitir un warning visible en la salida del CLI indicando que el perfil no pudo cargarse y continuar el análisis sin él (degradación graciosa), sin terminar con código de salida 2.

6. WHEN el usuario ejecuta `security-guardian init --profile` y ya existe un `.security-guardian.yml`, THE Security_Agent SHALL mostrar los valores actuales como defaults en cada pregunta del cuestionario, permitiendo al usuario confirmarlos o modificarlos.

7. THE `.security-guardian.yml` generado SHALL ser un archivo de texto plano legible, editable manualmente por el desarrollador, y apto para ser versionado en el repositorio de forma que todo el equipo comparta el mismo perfil de análisis.

8. WHEN se ejecuta `security-guardian init --profile` con el flag `--auto-detect`, THE Security_Agent SHALL escanear el directorio de trabajo actual para pre-rellenar automáticamente: `frameworks` (detectados desde `requirements.txt`, `package.json`, `pyproject.toml`, `Cargo.toml`), `auth_libraries` (detectados por presencia de imports conocidos como `bcrypt`, `django-allauth`, `passport`), y `min_severity` (inferido desde configuraciones de linters existentes como `.bandit`, `ruff.toml`); el cuestionario interactivo se ejecutará igualmente mostrando los valores detectados como defaults confirmables.

---

### Requisito 9: Observabilidad y trazabilidad del análisis

**User Story:** Como operador del servicio, quiero que cada análisis quede registrado con suficiente detalle para diagnosticar fallos y auditar decisiones del agente, para mantener la confiabilidad del sistema en producción.

#### Criterios de Aceptación

1. THE Security_Agent SHALL generar un identificador único de análisis (`analysis_id`) en formato UUID v4 al inicio de cada ejecución y propagarlo a todos los componentes durante esa ejecución.
2. WHEN cualquier componente (Static_Analyzer, CVE_Lookup, KB_Retriever, Bedrock_Client, PR_Commenter) inicia o completa una de las siguientes categorías de operación (inicio de análisis, consulta externa, invocación LLM, generación de comentario, escritura de resultado), THE Security_Agent SHALL registrar un evento de log estructurado en formato JSON con los campos: `timestamp` (ISO 8601 UTC), `analysis_id`, `componente`, `evento`, `duracion_ms` (incluido únicamente cuando la operación tiene un punto de inicio y fin medibles) y `detalle`. Los eventos de inicio sin par de finalización NO incluirán `duracion_ms`.
3. WHEN el razonamiento LLM completa la evaluación de un Finding candidato, THE Security_Agent SHALL registrar en el log un evento con los campos: `finding_id` (string), `es_explotable` (boolean), `severidad_ajustada` (string), `justificacion` (string) y `disposition` (string, valor exactamente `incluido` o `descartado`).
4. WHEN el Security_Agent completa un análisis exitosamente, THE Security_Agent SHALL registrar un evento de log de tipo `analysis_complete` con el resumen: número de Findings candidatos, número de Findings confirmados (`disposition: "incluido"`), número de falsos positivos descartados (`disposition: "descartado"`) y duración total en milisegundos.
5. IF cualquier componente experimenta un error cuyo tipo no admite reintento, o que persiste tras agotar todos los reintentos configurados, THEN THE Security_Agent SHALL registrar un evento de log de tipo `analysis_failed` con el `analysis_id`, el componente que falló, el mensaje de error y el stack trace, y publicar un comentario en el PR informando que el análisis no pudo completarse.
