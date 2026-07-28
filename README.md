# Security PR Guardian

Herramienta CLI y GitHub Action que analiza Pull Requests combinando **SAST** (análisis estático con regex sobre 7 CWEs), **escaneo de CVEs** vía OSV.dev, **RAG** sobre una base de conocimiento OWASP/CWE, y **razonamiento LLM** vía Amazon Bedrock para filtrar falsos positivos antes de publicar un comentario estructurado en el PR.

## Requisitos previos

- Python 3.11+
- Cuenta AWS con acceso a Amazon Bedrock y el modelo habilitado en tu región
- Token de GitHub con permisos `repo` (lectura) y `pull-requests` (escritura)

## Instalación

El paquete está publicado en PyPI. Instálalo con:

```bash
pip install security-pr-guardian
```

> Requiere Python 3.11 o superior.

## Configuración

### Variables de entorno obligatorias

```bash
export GITHUB_TOKEN=ghp_...              # Token GitHub
export BEDROCK_REGION=us-east-1          # Región AWS de Bedrock
export BEDROCK_MODEL_ID=anthropic.claude-sonnet-4-20250514-v1:0
```

Copia `.env.example` como `.env` y rellena los valores:

```bash
cp .env.example .env
```

### Configuración opcional (`config.yaml`)

```yaml
# config.yaml — opcional, en la raíz del proyecto
llm_backend: bedrock       # "bedrock" (default) | "anthropic"
osv_timeout_seconds: 10    # Timeout para OSV.dev (1-300)
max_diff_lines: 10000      # Máximo de líneas del diff a analizar
max_dependencies: 50       # Máximo de dependencias a escanear
```

## Uso

### Analizar un PR

```bash
security-guardian check --repo owner/repo --pr 42
```

Con opciones adicionales:

```bash
# Modo dry-run — no publica comentario en el PR
security-guardian check --repo owner/repo --pr 42 --no-comment

# Salida en JSON (útil para integración con otras herramientas)
security-guardian check --repo owner/repo --pr 42 --output json
```

### Códigos de salida

| Código | Significado |
|--------|-------------|
| `0` | Análisis completado, sin vulnerabilidades explotables |
| `1` | Análisis completado, al menos una vulnerabilidad explotable encontrada |
| `2` | Error de configuración o argumentos inválidos |

### Inicializar configuración

```bash
# Genera .env.example y valida las credenciales configuradas
security-guardian init

# Genera .security-guardian.yml con el perfil de convenciones del equipo
security-guardian init --profile

# Auto-detecta frameworks y librerías desde los manifiestos del proyecto
security-guardian init --profile --auto-detect
```

### Perfil de equipo (`.security-guardian.yml`)

Archivo opcional que personaliza el razonamiento del LLM para tu equipo:

```yaml
team_profile:
  frameworks:
    - django
    - react
  auth_libraries:
    - bcrypt
  allowed_patterns:
    - cwe_id: CWE-502
      razon: pickle usado solo en cache interno, nunca con input de usuario
    - cwe_id: CWE-327
      razon: md5 solo para ETags HTTP, no para datos sensibles
  min_severity: medium
  custom_exceptions:
    - Los logs internos pueden contener IDs de usuario por diseño
```

## Integración como GitHub Action

Agrega este step a tu workflow:

```yaml
- name: Security PR Guardian
  uses: Juanescuaran2041/security-sentinel@v0.1.0
  with:
    repo: ${{ github.repository }}
    pr-number: ${{ github.event.pull_request.number }}
    github-token: ${{ secrets.GITHUB_TOKEN }}
    bedrock-region: ${{ secrets.BEDROCK_REGION }}
    bedrock-model-id: ${{ secrets.BEDROCK_MODEL_ID }}
```

Configura los secrets en tu repositorio:
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` — credenciales AWS IAM
- `BEDROCK_REGION` — región de Bedrock (ej. `us-east-1`)
- `BEDROCK_MODEL_ID` — ID del modelo (ej. `anthropic.claude-3-5-haiku-20241022-v1:0`)

Ver el workflow de ejemplo completo en [`.github/workflows/security-guardian.yml`](.github/workflows/security-guardian.yml).

## Vulnerabilidades detectadas

| CWE | Tipo |
|-----|------|
| CWE-89 | Inyección SQL |
| CWE-78 | Inyección de comandos OS |
| CWE-79 | Cross-Site Scripting (XSS) |
| CWE-502 | Deserialización insegura |
| CWE-798 | Credenciales hardcodeadas |
| CWE-327 | Algoritmos criptográficos débiles (MD5, SHA1, DES) |
| CWE-552 | Referencias a rutas sensibles |

Además de CVEs conocidos en dependencias via [OSV.dev](https://osv.dev).

## Licencia

MIT
