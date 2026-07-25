# Case: XSS en Django vía mark_safe con input del usuario

## CVE

N/A (misuso recurrente de API de Django)

## CWE asociado

CWE-79

## Descripción

Django escapa HTML por defecto en templates. Sin embargo, `mark_safe()` y el filtro `|safe` desactivan el escapado. Cuando se aplican a contenido generado por usuarios, introducen XSS stored o reflected.

## Código vulnerable

```python
from django.utils.safestring import mark_safe

def render_user_bio(user):
    # PELIGROSO: mark_safe con contenido del usuario
    return mark_safe(f"<div class='bio'>{user.bio}</div>")

# En template:
# {{ user_comment|safe }}  ← también vulnerable
```

## Código corregido

```python
from django.utils.html import format_html, escape

def render_user_bio(user):
    # format_html escapa los argumentos automáticamente
    return format_html("<div class='bio'>{}</div>", user.bio)

# En template - dejar que Django escape normalmente:
# {{ user_comment }}  ← escapado por defecto

# Si necesitas HTML parcial, sanitizar primero:
import bleach
clean_bio = bleach.clean(user.bio, tags=['b', 'i', 'a'], attributes={'a': ['href']})
return mark_safe(clean_bio)  # OK porque bleach ya sanitizó
```

## Contexto

`mark_safe` es necesario para HTML generado por el servidor (widgets de forms, HTML estático). El error es aplicarlo a datos del usuario. `format_html()` es la alternativa segura que escapa los argumentos interpolados.

## Referencia

- https://docs.djangoproject.com/en/stable/ref/utils/#django.utils.safestring.mark_safe
- https://docs.djangoproject.com/en/stable/ref/utils/#django.utils.html.format_html
