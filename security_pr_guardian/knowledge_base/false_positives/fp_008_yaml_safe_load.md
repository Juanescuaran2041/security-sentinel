# False Positive: yaml.load() con SafeLoader o yaml.safe_load()

## Patrón que dispara el detector

```python
yaml.load(data, Loader=yaml.SafeLoader)
yaml.safe_load(data)
yaml.load(stream, Loader=yaml.BaseLoader)
```

## CWE reportado

CWE-502 (Deserialization of Untrusted Data)

## Por qué NO es vulnerable en estos contextos

El detector busca `yaml.load(` como patrón de deserialización insegura. Pero PyYAML ofrece loaders seguros que solo permiten tipos básicos:

- **`yaml.safe_load()`**: solo permite str, int, float, bool, None, list, dict
- **`yaml.load(data, Loader=yaml.SafeLoader)`**: equivalente a safe_load
- **`yaml.load(data, Loader=yaml.BaseLoader)`**: aún más restrictivo, todo es string

Ninguno de estos permite `!!python/object` ni ejecuta código.

## Criterio para descartar como falso positivo

Si el código:
- Usa **`yaml.safe_load()`** — siempre seguro
- Usa **`yaml.load()` con `Loader=yaml.SafeLoader`** o `Loader=yaml.BaseLoader`
- Usa **`yaml.load()` con un Loader custom** que NO hereda de `yaml.FullLoader` o `yaml.UnsafeLoader`

→ **Disposición**: no explotable, severidad INFO

## Criterio para CONFIRMAR como verdadero positivo

Si el código:
- Usa **`yaml.load(data)`** sin argumento Loader (FullLoader por defecto en PyYAML 6+, pero UnsafeLoader en versiones antiguas)
- Usa **`yaml.load(data, Loader=yaml.FullLoader)`** con datos de fuente no confiable
- Usa **`yaml.load(data, Loader=yaml.UnsafeLoader)`** — explícitamente inseguro
- Usa **`yaml.unsafe_load(data)`**

→ **Disposición**: explotable, severidad CRITICAL

## Ejemplo de código seguro (falso positivo)

```python
import yaml

# safe_load — solo tipos básicos
with open("config.yaml") as f:
    config = yaml.safe_load(f)

# Loader explícito seguro
data = yaml.load(user_uploaded_yaml, Loader=yaml.SafeLoader)
```

## Ejemplo de código vulnerable (verdadero positivo)

```python
# Sin Loader — peligroso con datos no confiables
config = yaml.load(user_input)  # VULNERABLE en PyYAML < 6.0

# UnsafeLoader explícito
data = yaml.load(file_data, Loader=yaml.UnsafeLoader)  # VULNERABLE
```
