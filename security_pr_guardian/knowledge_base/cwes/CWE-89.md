# CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)

## Descripción

SQL Injection ocurre cuando input no confiable del usuario se inserta directamente en una consulta SQL sin sanitización ni parametrización. El atacante puede modificar la lógica de la query para leer, modificar o eliminar datos arbitrarios.

## Impacto

- Lectura no autorizada de toda la base de datos
- Modificación o borrado de registros
- Bypass de autenticación y autorización
- En algunos DBMS (MySQL, MSSQL), ejecución de comandos del sistema operativo
- Escalamiento a RCE completo en configuraciones permisivas

## Vectores de ataque comunes

- Concatenación directa: `f"SELECT * FROM users WHERE id = {user_id}"`
- Format strings: `"SELECT * FROM users WHERE name = '%s'" % name`
- String formatting con `.format()`: `"...WHERE id = {}".format(input)`
- ORM con raw queries: `Model.objects.raw(f"SELECT ... {input}")`
- Stored procedures llamadas con input sin validar

## Patrones vulnerables típicos

```python
# Python - concatenación directa
cursor.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")

# Python - format string
query = "SELECT * FROM products WHERE name = '%s'" % user_input
cursor.execute(query)

# Django - raw query insegura
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")

# Node.js
db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`)
```

## Remediación

- **Usar parameterized queries / prepared statements siempre**
- Usar el ORM correctamente sin raw SQL con input externo
- Validar input con whitelist (tipo, longitud, caracteres permitidos)
- Aplicar principio de mínimo privilegio en el usuario de BD
- Nunca construir queries con concatenación de strings

## Código corregido

```python
# Python - parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (request.args['id'],))

# Django ORM - forma segura
User.objects.filter(username=username)

# SQLAlchemy - parameterized
session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
```

## OWASP relacionado

- A03:2021 — Injection

## Referencias

- https://cwe.mitre.org/data/definitions/89.html
- https://owasp.org/Top10/A03_2021-Injection/
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
