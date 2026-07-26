# False Positive: Variable llamada "password" sin ser credencial hardcodeada

## Patrón que dispara el detector

```python
password = "algún string"
secret = "valor"
api_key = "..."
token = "..."
```

## CWE reportado

CWE-798 (Use of Hard-coded Credentials)

## Por qué NO es vulnerable en estos contextos

El detector busca asignaciones a variables con nombres sugestivos (`password`, `secret`, `api_key`, `token`) con valores de string literal. Pero hay contextos donde estos nombres se usan sin ser credenciales reales:

- **Nombres de campo/columna**: referencia al nombre del campo, no al valor
- **Placeholders en tests**: datos de prueba que no son secretos reales
- **Constantes de validación**: regex patterns, nombres de headers, keys de dict
- **Documentación inline**: ejemplos en docstrings o comments
- **Hashing/comparison logic**: la variable recibe un valor calculado, no hardcodeado

## Criterio para descartar como falso positivo

Si la asignación:
- Está en un **archivo de test** (`test_*.py`, `*_test.py`, `conftest.py`)
- El valor es claramente un **placeholder**: `"changeme"`, `"test"`, `"example"`, `"xxx"`
- Es una **referencia a un nombre de campo**: `password_field = "password"`, `column = "api_key"`
- Es una **constante de configuración de nombre**: `PASSWORD_HEADER = "X-Auth-Password"`
- Está en un **docstring o comentario**
- Lee el valor real de otra fuente: `password = os.environ["DB_PASSWORD"]`

→ **Disposición**: no explotable, severidad INFO

## Criterio para CONFIRMAR como verdadero positivo

Si la asignación:
- Contiene un valor que **parece una credencial real** (longitud > 8, mezcla de caracteres)
- Tiene formato de API key conocido (`sk-`, `ghp_`, `AKIA`, `xoxb-`)
- Se usa directamente en autenticación sin pasar por env vars o secrets manager
- Está en código de producción (no tests)

→ **Disposición**: explotable, severidad HIGH

## Ejemplo de código seguro (falso positivo)

```python
# Test fixture — no es un secreto real
def test_login():
    password = "test_password_123"
    response = client.post("/login", json={"password": password})

# Nombre de campo, no el valor
PASSWORD_FIELD = "password"
columns = ["username", "password", "email"]

# Lectura de env var (el nombre de variable es "password" pero el valor viene del entorno)
password = os.environ.get("DB_PASSWORD", "")
```

## Ejemplo de código vulnerable (verdadero positivo)

```python
# Credencial real hardcodeada — SÍ es vulnerable
DATABASE_PASSWORD = "pr0duction_s3cret_2024!"
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678"
```
