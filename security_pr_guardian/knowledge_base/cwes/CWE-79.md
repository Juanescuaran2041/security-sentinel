# CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting / XSS)

## Descripción

XSS ocurre cuando una aplicación incluye datos no confiables en una página web sin validación o escapado apropiado. Permite al atacante ejecutar scripts arbitrarios en el navegador de la víctima dentro del contexto de la aplicación vulnerable.

## Impacto

- Robo de cookies de sesión y tokens de autenticación
- Keylogging y captura de credenciales
- Defacement del sitio web
- Redirección a sitios maliciosos
- Ejecución de acciones en nombre del usuario (CSRF implícito)

## Tipos

- **Reflected XSS**: el payload viene del request y se refleja en la respuesta
- **Stored XSS**: el payload se persiste (DB, archivo) y se muestra a otros usuarios
- **DOM-based XSS**: la manipulación ocurre enteramente en el cliente vía JavaScript

## Patrones vulnerables típicos

```python
# Python Flask - respuesta HTML sin escapar
@app.route("/search")
def search():
    q = request.args.get("q")
    return f"<h1>Resultados para: {q}</h1>"

# Jinja2 sin autoescape
template = Template("Hello {{ name }}")  # sin Environment con autoescape

# Django - mark_safe con input del usuario
from django.utils.safestring import mark_safe
return mark_safe(f"<div>{user_comment}</div>")
```

```javascript
// JavaScript - innerHTML con input
document.getElementById("output").innerHTML = userInput;

// React - dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userContent}} />
```

## Remediación

- **Activar autoescape en templates** (Jinja2: `autoescape=True`, Django: activado por defecto)
- Nunca usar `mark_safe()`, `|safe`, o `dangerouslySetInnerHTML` con input del usuario
- Usar Content-Security-Policy headers restrictivos
- Sanitizar HTML con librerías como `bleach` (Python) o `DOMPurify` (JS)
- Encodear output según contexto (HTML entity, JS string, URL, CSS)

## Código corregido

```python
# Flask con Jinja2 autoescape (comportamiento por defecto en render_template)
from flask import render_template
return render_template("search.html", query=q)  # auto-escaped

# Escapado manual si es necesario
from markupsafe import escape
return f"<h1>Resultados para: {escape(q)}</h1>"
```

## OWASP relacionado

- A03:2021 — Injection (XSS es un subtipo de injection en el navegador)

## Referencias

- https://cwe.mitre.org/data/definitions/79.html
- https://owasp.org/Top10/A03_2021-Injection/
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
