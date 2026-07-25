# Case: SQL Injection en WordPress (CVE-2022-21661)

## CVE

CVE-2022-21661

## CWE asociado

CWE-89

## Descripción

WordPress antes de 5.8.3 era vulnerable a SQL injection vía la clase WP_Query. Un usuario autenticado con capacidad de crear posts (contributor+) podía inyectar SQL a través de parámetros de tax_query cuando se usaban en combinación con ciertos plugins.

## Código vulnerable

```php
// Plugin que pasa input del usuario directamente a WP_Query
$args = array(
    'tax_query' => array(
        array(
            'taxonomy' => $_GET['taxonomy'],
            'terms' => $_GET['term'],
        )
    )
);
$query = new WP_Query($args);
```

## Código corregido

```php
// Validar contra taxonomías registradas
$taxonomy = sanitize_key($_GET['taxonomy']);
if (!taxonomy_exists($taxonomy)) {
    wp_die('Invalid taxonomy');
}
$term = absint($_GET['term']);  // solo IDs numéricos
$args = array(
    'tax_query' => array(
        array(
            'taxonomy' => $taxonomy,
            'terms' => $term,
            'field' => 'term_id',
        )
    )
);
```

## Contexto

WP_Query internamente construía fragmentos SQL para tax queries sin sanitizar completamente los valores. Core WordPress parcheó la clase WP_Tax_Query para escapar todos los inputs.

## Referencia

- https://nvd.nist.gov/vuln/detail/CVE-2022-21661
- https://wordpress.org/news/2022/01/wordpress-5-8-3-security-release/
