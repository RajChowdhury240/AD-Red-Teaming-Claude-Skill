# AD-Red-Teaming-Claude-Skill
#### A Dedicated claude skill for hacking Active Directory

  Recon / Enumeration

  - LDAP anonymous bind — query DC without creds via null session
  - SMB null session — enum users/shares anonymously on legacy DCs
  - RID cycling — enum SIDs via SAMR to dump users without creds
  - SPN scanning — setspn -Q */* or LDAP filter to find service accounts
  - BloodHound collection — SharpHound/BloodHound.py to map attack paths
  - PowerView / ADExplorer — domain object enumeration
  - DNS zone transfer — AXFR against DC DNS for full record dump
  - Username enum via Kerberos — pre-auth error code differences (KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN vs preauth required)
  - GPO enumeration — find vulnerable GPP cpassword in SYSVOL
  - LAPS readability check — ExtendedRight ms-Mcs-AdmPwd read access

  Credential Access

  - Kerberoasting — request TGS for SPN accounts, crack RC4/AES hash offline
  - AS-REP Roasting — accounts with DONT_REQ_PREAUTH leak crackable hash
  - Timeroasting — abuse NTP authentication to crack computer account hashes
  - GPP cpassword — decrypt Groups.xml AES key (public Microsoft key)
  - LSASS dump — Mimikatz/comsvcs.dll/procdump for plaintext + hashes
  - DCSync — replicate creds via DRSUAPI with Replicating Directory Changes rights
  - DCShadow — register rogue DC, push malicious replication
  - NTDS.dit extraction — VSS shadow copy or ntdsutil ifm for offline hash dump
  - SAM/SECURITY hive dump — local hash extraction
  - Credential Manager / DPAPI — masterkey decryption for stored creds
  - LSA secrets — service account passwords in registry
  - Cached domain creds (MSCache v2) — crack with hashcat mode 2100
  - WDigest downgrade — UseLogonCredential=1 forces plaintext in LSASS
  - SSP injection — load mimilib.dll for credential capture
  - Browser/credential file harvest — Chrome/Edge DPAPI-protected stores
  - KeePass/keylogger — KeeFarce, KeeThief from process memory
  - ProcDump on LSASS — signed binary, evade some EDR
  - MiniDump via PPL bypass — disable PPL with mimikatz !processprotect

  Coerced Authentication

  - PetitPotam — MS-EFSRPC coerce DC auth to attacker
  - PrinterBug (SpoolSample) — MS-RPRN spooler coerce
  - DFSCoerce — MS-DFSNM coerce, often unpatched
  - ShadowCoerce — MS-FSRVP volume shadow copy coerce
  - WebDAV coerce (PrivExchange-style) — HTTP-based NTLM coerce
  - WSUS coerce — abuse update server auth flows
  - Certifried-style coerce + ADCS — chain to domain admin
  - MS-EVEN6 / MS-EFSR / MS-RPRN — various RPC-based coerces

  Relay Attacks

  - NTLM relay to LDAP/LDAPS — RBCD or ACL write
  - NTLM relay to SMB — execute cmds (signing disabled)
  - NTLM relay to ADCS HTTP (ESC8) — request cert as victim → DA
  - NTLM relay to MSSQL — xp_cmdshell as relayed user
  - NTLM relay to EWS/Exchange — mailbox access, PrivExchange
  - Kerberos relay (KrbRelay/KrbRelayUp) — LSARPC/RPC SSPI relay local→DA
  - NTLM reflection (CVE-2019-1384 / RemotePotato0) — relay back to self for SYSTEM
  - mitm6 + ntlmrelayx — IPv6 DHCP/DNS poison → WPAD → relay
  - LLMNR/NBT-NS/mDNS poisoning — Responder capture/relay NetNTLM hashes
  - ADIDNS poisoning — write DNS records via authenticated user

  Kerberos Attacks

  - Pass-the-Ticket (PtT) — inject TGT/TGS into session
  - Pass-the-Hash (PtH) — NTLM hash for auth without password
  - OverPass-the-Hash — hash → request TGT → Kerberos auth
  - Pass-the-Key (AES) — AES256 key auth
  - Golden Ticket — forge TGT with krbtgt hash, arbitrary user/groups
  - Silver Ticket — forge TGS for specific service with service hash
  - Diamond Ticket — modify legit TGT (PAC manipulation)
  - Sapphire Ticket — Diamond + S4U2self for stealth
  - Skeleton Key — patch LSASS for universal master password
  - PAC validation bypass — sAMAccountName spoofing (CVE-2021-42278/42287, noPac)
  - Bronze Bit (CVE-2020-17049) — bypass S4U2proxy delegation restriction
  - Kerberos downgrade to RC4 — force weaker etype for crack
  - U2U abuse — user-to-user TGS for impersonation
  - FAST/Kerberos armoring bypass

  Delegation Abuse

  - Unconstrained Delegation (TRUSTED_FOR_DELEGATION) — capture TGTs of inbound auths, coerce DC
  - Constrained Delegation (S4U2proxy) — abuse SPN list for service impersonation
  - Protocol Transition (S4U2self) — request ticket as any user without their creds
  - Resource-Based Constrained Delegation (RBCD) — write msDS-AllowedToActOnBehalfOfOtherIdentity, S4U full DA on
  target
  - Machine account quota abuse (MAQ=10) — create computer, set RBCD, take over host
  - Delegation chain abuse — link CD/RBCD across hosts

  ACL / ACE Abuse

  - GenericAll — full control on object, reset password / RBCD / shadow creds
  - GenericWrite — write attributes, set SPN (targeted Kerberoast) or logonScript
  - WriteOwner — take ownership, then GenericAll
  - WriteDACL — modify ACL to grant self GenericAll
  - WriteProperty on member — add self to privileged group
  - Self-membership / WriteProperty Self — add self to group
  - ForceChangePassword — reset user password without knowing old
  - AllExtendedRights — DCSync, LAPS read, password reset
  - ReadGMSAPassword — read msDS-ManagedPassword for gMSA
  - AddAllowedToAct — set RBCD on target
  - AddKeyCredentialLink — Shadow Credentials (msDS-KeyCredentialLink)
  - AddSelf to group — abuse Self ACE on group
  - GPO edit (WriteProperty on gpLink/gPCFileSysPath) — RCE on linked OUs
  - Logon script write — drop payload in NETLOGON/SYSVOL

  Shadow Credentials

  - msDS-KeyCredentialLink abuse — Whisker/pyWhisker add cert, PKINIT auth → NT hash via UnPAC

  ADCS (Certificate Services)

  - ESC1 — template allows SAN + client auth + low-priv enroll → impersonate DA
  - ESC2 — Any Purpose EKU, similar to ESC1
  - ESC3 — Enrollment Agent template abuse, request on behalf of
  - ESC4 — vulnerable template ACL (write) → modify to ESC1
  - ESC5 — vulnerable PKI object ACLs (CA, NTAuthCertificates)
  - ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA → SAN injection
  - ESC7 — CA ACL allows ManageCA/ManageCertificates → approve denied requests
  - ESC8 — HTTP enrollment endpoint NTLM relay
  - ESC9 — no security extension flag → cert mapping bypass
  - ESC10 — weak cert mapping (StrongCertificateBindingEnforcement)
  - ESC11 — RPC enrollment relay (no IF_ENFORCEENCRYPTICERTREQUEST)
  - ESC12 — YubiHSM key extract from CA
  - ESC13 — OID group link abuse → cross-template group privesc
  - ESC14 — altSecurityIdentities mapping abuse
  - ESC15 (EKUwu) — schema v1 template arbitrary EKU injection
  - ESC16 — security extension disabled domain-wide
  - Certifried (CVE-2022-26923) — machine account cert, dNSHostName spoof → DA
  - Golden Certificate — steal CA private key, forge any cert
  - Certificate theft — DPAPI/MY store extraction (Certify, SharpDPAPI)

  Group Policy Attacks

  - GPO modification — write to gPCFileSysPath in SYSVOL
  - SharpGPOAbuse — add scheduled task / immediate task / rights
  - GPP cpassword (legacy) — Groups.xml decrypt
  - MSI/Software Installation GPO — push malicious MSI
  - Logon/Startup script abuse

  Trust Attacks

  - SID History injection — golden ticket with foreign SID for cross-domain DA
  - Inter-Forest TGT (printer bug across trust) — coerce trust DC
  - SID filtering bypass — quarantine flag misconfig
  - Trust key extraction — forge inter-realm TGT
  - Foreign Security Principal abuse
  - Cross-forest Kerberoast
  - AzureAD Connect / PHS sync abuse — MSOL account password → DCSync

  Lateral Movement

  - PsExec / SMBExec — admin SMB write + service create
  - WMIExec / WMI — DCOM, no SMB write
  - DCOM (MMC20.Application, ShellWindows, ShellBrowserWindow) — lateral exec
  - WinRM / Evil-WinRM — port 5985/5986
  - RDP (MSTSC, hash via restricted admin)
  - SCM remote service create
  - AT / scheduled task remote
  - PowerShell Remoting (Enter-PSSession, Invoke-Command)
  - Pass-the-Ticket lateral — TGS for CIFS/HOST
  - RDPInception / RDP hijack (tscon SYSTEM)
  - Token impersonation (incognito) — steal logged-on tokens

  Persistence

  - Golden Ticket — krbtgt long-term forgery
  - Silver Ticket — service-specific stealth
  - Skeleton Key — LSASS patch
  - DSRM password sync — DC local admin
  - AdminSDHolder ACL backdoor — re-applied every 60 min via SDProp
  - Custom SSP / SSPI hijack
  - GPO persistence
  - Service account with non-expiring password
  - Hidden user with denyACL on enum
  - Krbtgt service principal modification

  Misc / Modern

  - sAMAccountName spoofing (noPac, CVE-2021-42278/42287)
  - Zerologon (CVE-2020-1472) — Netlogon empty AES → DC machine pwd reset
  - PrintNightmare (CVE-2021-1675/34527) — point and print RCE
  - SeriousSAM / HiveNightmare (CVE-2021-36934) — local SAM read
  - Petit/Print/Shadow/DFS coerce chains → ADCS ESC8 → DA
  - LDAP signing not required + channel binding off — relay viable
  - SMB signing disabled — relay viable
  - IPv6 + WPAD (mitm6)
  - WSUS HTTP MITM — push malicious update
  - MSSQL trust links — EXECUTE AS LOGIN, openrowset, xp_cmdshell chain to DA
  - Exchange privileged groups (pre-2019) — WriteDACL on domain
  - SCCM/MECM relay (TAKEOVER attacks) — NAA cred extract, PXE boot, cross-site escalation
  - gMSA reading + golden gMSA forge — root key knowledge → forge any gMSA pwd
  - LAPS read → local admin reuse
  - Pre-Windows 2000 compat group — anonymous query
  - Backup operators → registry hive dump → SAM/SECURITY → DA
  - Server Operators → service binPath swap on DC
  - Account Operators → user creation/reset on non-admins
  - DnsAdmins → ServerLevelPluginDll DLL injection (legacy)
  - Schema Admins → schema modify, indirect path
  - Print Operators → driver load on DC
  - Hyper-V Admins → DC VM disk access offline
  - Storage Replica Admins / Cert Publishers — niche group abuse
  - Pre-auth bruteforce (kerbrute) — slow spray, no lockout on TGT request
  - AS-REQ password spray — domain spray with low lockout
  - Targeted Kerberoast (write SPN on user with GenericWrite)
  - RPC filter bypass / EFSRPC patched bypass variants
  - Authentication Silos / PAW bypass
  - Tier-0 trust violation via service account pivots

  Bonus Niche

  - Logon script SMB hijack — race write to NETLOGON
  - Sysvol DFSR replica MITM
  - DFS namespace abuse
  - ms-DS-MachineAccountQuota = 0 still bypassable via owner CreateChild
  - Pre-2k computer accounts (default password = lowercase name)
  - GPO immediate scheduled task XML injection
  - Subnet object writes → site-link manipulation → replication path control
  - WSMan/CredSSP double-hop creds left in memory
  - Restricted Admin RDP → hash-only auth
  - Protected Users group bypass via NTLM fallback
