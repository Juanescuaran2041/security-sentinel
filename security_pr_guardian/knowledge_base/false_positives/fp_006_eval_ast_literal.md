# False Positive: eval() que en realidad es ast.literal_eval() o constante

## Patrón que dispara el detector

```python
eval(expression)
eval("some string")
```

## CWE reportado

CWE-502 (Deserialization of Untrusted Data) / CWE-94 (Code Injection)

## Por qué NO es vulnerable en estos contextos

El detector marca cualquier uso de `eval()`. Pero hay patrones donde eval no ejecuta código arbitrario del usuario:

- **`ast.literal_eval()`**: solo parsea literales Python (strings, numbers, tuples, lists, dicts) — NO ejecuta código
- **eval con constantes**: expresiones fijas sin input externo
- **eval en notebooks/REPL interactivo**: código del desarrollador, no del atacante
- **Configuración estática evaluada una vez**: expresiones de config que no vienen del usuario

## Criterio para descartar como falso positivo

Si el código:
- Usa **`ast.literal_eval()`** en lugar de `eval()` — es seguro por diseño
- El argumento de eval es un **string literal** o constante (no input externo)
- Está en un **notebook o script interactivo** (no código de servidor)
- El input fue **previamente validado** contra un patrón regex estricto (solo dígitos, operadores aritméticos)

→ **Disposición**: no explotable, severidad INFO

## Criterio para CONFIRMAR como verdadero positivo

Si:
- Es `eval()` (no `ast.literal_eval()`) con input que proviene del request/usuario
- El input no tiene validación previa o tiene validación blacklist (insuficiente)
- Se ejecuta en contexto de servidor web con acceso a módulos peligrosos

→ **Disposición**: explotable, severidad CRITICAL

## Ejemplo de código seguro (falso positivo)

```python
import ast

# ast.literal_eval — solo parsea literales, no ejecuta código
user_input = request.form.get("data")
parsed = ast.literal_eval(user_input)  # solo acepta: "{'key': 'value'}", "[1,2,3]", etc.
# Lanza ValueError si el input contiene llamadas a funciones o imports

# eval con constante — no hay input externo
DEFAULT_CONFIG = eval("{'debug': False, 'port': 8080}")  # literal, no user input
```

## Ejemplo de código vulnerable (verdadero positivo)

```python
# eval con input del usuario — RCE directo
expression = request.args.get("calc")
result = eval(expression)  # VULNERABLE: __import__('os').system('rm -rf /')
```
