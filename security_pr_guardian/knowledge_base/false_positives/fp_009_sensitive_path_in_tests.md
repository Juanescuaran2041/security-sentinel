# False Positive: Referencia a /etc/passwd en tests o documentación

## Patrón que dispara el detector

```python
"/etc/passwd"
"/etc/shadow"
"~/.ssh/id_rsa"
```

## CWE reportado

CWE-552 (Files or Directories Accessible to External Parties)

## Por qué NO es vulnerable en estos contextos

El detector busca strings que contengan rutas de archivos sensibles. Pero estas strings aparecen frecuentemente en código que no accede a esos archivos:

- **Tests de seguridad**: verifican que el sistema NO permite acceso a rutas sensibles
- **Documentación y comentarios**: mencionan rutas como ejemplo de lo que proteger
- **Validación negativa**: código que BLOQUEA acceso a rutas peligrosas (allowlist/denylist)
- **Strings de error/log**: mensajes que mencionan rutas sin accederlas
- **Análisis estático propio**: reglas que detectan acceso a rutas sensibles (como nuestro PatternEngine)

## Criterio para descartar como falso positivo

Si la referencia a la ruta sensible:
- Está en un **archivo de test** (`test_*.py`, fixtures)
- Es parte de una **denylist o blocklist** (el código la BLOQUEA, no la accede)
- Está en un **comentario o docstring** como documentación
- Es un **mensaje de error** o string de log
- Es parte de una **regex de detección** (análisis estático)
- No hay `open()`, `read()`, `Path().read_text()` sobre esa ruta

→ **Disposición**: no explotable, severidad INFO

## Criterio para CONFIRMAR como verdadero positivo

Si la referencia:
- Se usa con **`open()`**, **`Path.read_text()`**, o **`os.path.exists()`** seguido de lectura
- Se concatena con input del usuario (path traversal)
- El código efectivamente **lee o escribe** al archivo sensible en runtime

→ **Disposición**: explotable, severidad HIGH

## Ejemplo de código seguro (falso positivo)

```python
# Test que verifica que path traversal está bloqueado
def test_blocks_sensitive_paths():
    response = client.get("/download?file=../../etc/passwd")
    assert response.status_code == 403

# Denylist — el código PROTEGE contra acceso
BLOCKED_PATHS = ["/etc/passwd", "/etc/shadow", "~/.ssh/"]
def is_blocked(path: str) -> bool:
    return any(blocked in path for blocked in BLOCKED_PATHS)

# Regex en pattern engine (nuestro propio código)
SENSITIVE_PATH_PATTERN = r'(/etc/passwd|/etc/shadow|~/\.ssh/)'
```

## Ejemplo de código vulnerable (verdadero positivo)

```python
# Lectura real de archivo sensible
with open("/etc/passwd") as f:
    users = f.read()  # VULNERABLE — expone info del sistema
```
