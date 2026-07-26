# False Positive: Interpolación en template con autoescape activo

## Patrón que dispara el detector

```python
return f"<div>{variable}</div>"
render_template("page.html", name=user_input)
```

## CWE reportado

CWE-79 (Cross-site Scripting / XSS)

## Por qué NO es vulnerable en estos contextos

Frameworks modernos aplican autoescape por defecto en templates. El detector puede marcar código que parece interpolar variables en HTML, pero el framework ya sanitiza:

- **Django templates**: autoescape ON por defecto — `{{ variable }}` se escapa automáticamente
- **Flask/Jinja2 render_template()**: autoescape ON para archivos .html
- **React JSX**: todo se escapa por defecto (excepto dangerouslySetInnerHTML)
- **Vue.js `{{ }}`**: interpolación de texto siempre escapa HTML

## Criterio para descartar como falso positivo

Si el código:
- Usa **`render_template()`** de Flask (Jinja2 con autoescape en .html)
- Usa **templates Django** sin `|safe` ni `mark_safe()` en el valor del usuario
- Usa **React JSX** con `{}` (no `dangerouslySetInnerHTML`)
- El HTML se genera por el **framework con escapado automático activado**
- Las variables se pasan a un **template engine con autoescape**, no se concatenan en strings

→ **Disposición**: no explotable, severidad INFO

## Criterio para CONFIRMAR como verdadero positivo

Si el código:
- Usa **`mark_safe()`**, `|safe`, `{% autoescape off %}` con datos del usuario
- Construye HTML con **f-strings o concatenación** sin escapar (fuera de template engine)
- Usa **`dangerouslySetInnerHTML`** o `v-html` con input sin sanitizar
- El framework tiene autoescape **desactivado** globalmente
- Retorna respuestas `text/html` directamente con variables interpoladas

→ **Disposición**: explotable, severidad HIGH

## Ejemplo de código seguro (falso positivo)

```python
# Flask render_template — autoescape activo por defecto en .html
from flask import render_template
return render_template("profile.html", username=user_input)
# En el template: <h1>{{ username }}</h1>  ← escapado automáticamente

# Django template — autoescape activo por defecto
# template.html: <p>{{ comment }}</p>  ← escapado
```

## Ejemplo de código vulnerable (verdadero positivo)

```python
# f-string retornado como HTML — sin escapar
return f"<h1>Hola {user_input}</h1>"  # VULNERABLE

# Django mark_safe con input del usuario
from django.utils.safestring import mark_safe
return mark_safe(f"<div>{user_comment}</div>")  # VULNERABLE
```
