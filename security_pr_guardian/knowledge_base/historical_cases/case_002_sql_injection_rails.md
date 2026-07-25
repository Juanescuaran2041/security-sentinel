# Case: SQL Injection en Ruby on Rails (CVE-2012-2661)

## CVE

CVE-2012-2661

## CWE asociado

CWE-89

## Descripción

Ruby on Rails antes de 3.0.13, 3.1.x antes de 3.1.5, y 3.2.x antes de 3.2.4 permitía SQL injection vía valores crafteados en el hash de condiciones del método `where()`. El parser no sanitizaba adecuadamente ciertos operadores.

## Código vulnerable

```ruby
# El atacante enviaba params[:id] como un hash con operadores SQL
User.where(id: params[:id])
# Con params[:id] = {"1 OR 1=1--" => "1"}
```

## Código corregido

```ruby
# Validar tipo antes de usar en query
user_id = Integer(params[:id])
User.where(id: user_id)
```

## Contexto

ActiveRecord confiaba en que los valores del hash serían tipos simples. Un atacante podía pasar estructuras anidadas que el parser convertía en fragmentos SQL sin escapar.

## Referencia

- https://nvd.nist.gov/vuln/detail/CVE-2012-2661
- https://groups.google.com/g/rubyonrails-security/c/8SA-M3as7A8
