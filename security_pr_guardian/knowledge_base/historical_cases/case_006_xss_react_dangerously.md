# Case: XSS via dangerouslySetInnerHTML en React (patrón recurrente)

## CVE

N/A (patrón de vulnerabilidad recurrente en aplicaciones React)

## CWE asociado

CWE-79

## Descripción

React escapa HTML por defecto en JSX, pero `dangerouslySetInnerHTML` bypassa esta protección. Cuando se usa con contenido generado por usuarios (comentarios, perfiles, posts), permite stored XSS que afecta a todos los visitantes de la página.

## Código vulnerable

```jsx
function Comment({ comment }) {
    // El usuario puede inyectar <script> o event handlers
    return <div dangerouslySetInnerHTML={{__html: comment.body}} />;
}

// También vulnerable: innerHTML en useRef
function UserProfile({ bio }) {
    const ref = useRef(null);
    useEffect(() => {
        ref.current.innerHTML = bio;  // XSS
    }, [bio]);
    return <div ref={ref} />;
}
```

## Código corregido

```jsx
import DOMPurify from 'dompurify';

function Comment({ comment }) {
    // Sanitizar HTML antes de renderizar
    const clean = DOMPurify.sanitize(comment.body, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
        ALLOWED_ATTR: ['href']
    });
    return <div dangerouslySetInnerHTML={{__html: clean}} />;
}

// Mejor: usar texto plano si no necesitas HTML
function SafeComment({ comment }) {
    return <div>{comment.body}</div>;  // React escapa automáticamente
}
```

## Contexto

El nombre `dangerouslySetInnerHTML` es intencional — React advierte sobre el riesgo. Pero desarrolladores lo usan sin sanitización para renderizar rich text de usuarios (markdown convertido a HTML, editores WYSIWYG).

## Referencia

- https://owasp.org/www-community/attacks/xss/
- https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
