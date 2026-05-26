# HTB Machine Report — Meow

**Date:** 2026-05-25
**Author:** Franksimon
**Platform:** Hack The Box — Starting Point
**Difficulty:** Very Easy
**OS:** Linux
**IP:** 10.129.18.136
**Status:** Pwned

---

## 1. Executive Summary

Meow es una máquina Linux de nivel introductorio que expone un servicio Telnet (puerto 23) sin autenticación. El usuario `root` acepta login con contraseña en blanco, otorgando acceso directo al sistema con máximos privilegios. No requiere escalación de privilegios.

---

## 2. Enumeration

### 2.1 Port Scan

```bash
nmap -sC -sV -oA nmap/initial 10.129.18.136
```

**Resultado:**

| Port  | State | Service | Version        |
|-------|-------|---------|----------------|
| 23/tcp | open | telnet  | Linux telnetd  |

TTL=63 confirma sistema Linux.

### 2.2 Service Enumeration

Un único servicio expuesto. Telnet en puerto 23 sin banner adicional. Superficie de ataque mínima pero crítica.

---

## 3. Vulnerability Identification

| # | Vulnerability | CVE | CVSS | Location |
|---|--------------|-----|------|----------|
| 1 | Telnet sin autenticación (root sin password) | — | 10.0 | Puerto 23 |
| 2 | Protocolo inseguro en texto plano | — | 7.5 | Puerto 23 |

**Por qué es explotable:**
Telnet no cifra el tráfico y en este caso el usuario `root` no tiene contraseña configurada. Cualquier atacante con acceso de red puede obtener una shell como root sin credenciales.

---

## 4. Exploitation

### 4.1 Acceso inicial — Telnet sin contraseña

```bash
telnet 10.129.18.136
# login: root
# Password: [Enter — en blanco]
```

**Resultado:** Shell interactiva como `root` de forma inmediata.

---

## 5. Post-Exploitation

### 5.1 Root Flag

```bash
cat /root/flag.txt
```

**Root flag:** `b40abdfe23665f766f9c61ecba8a4c19`

No se requirió escalación de privilegios — acceso directo como root.

---

## 6. Remediation

| Finding | Recommendation | Priority |
|---------|---------------|----------|
| Telnet expuesto | Deshabilitar Telnet, reemplazar con SSH | Critical |
| root sin password | Establecer contraseña robusta para root | Critical |
| Protocolo en texto plano | Usar protocolos cifrados (SSH, TLS) | High |

---

## 7. Lessons Learned

- Siempre probar credenciales por defecto o en blanco antes de intentar exploits complejos.
- TTL=63 en ping → Linux (TTL=127 → Windows).
- Telnet sigue apareciendo en entornos legacy, routers, y dispositivos IoT.

> **OSCP note:** En el examen, si ves el puerto 23 abierto, lo primero es probar `root` sin password y usuarios comunes (`admin`, `guest`, `user`). Es raro pero existe en redes reales.

---

## 8. References

- HTB Starting Point — Meow
- Telnet RFC 854: protocolo sin cifrado por diseño
