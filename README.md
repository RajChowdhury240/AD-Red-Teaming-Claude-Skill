# AD-Red-Teaming-Claude-Skill
#### A Dedicated claude skill for hacking Active Directory

  ### Recon / Enumeration

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

  ### Credential Access

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

  ### Coerced Authentication

  - PetitPotam — MS-EFSRPC coerce DC auth to attacker
  - PrinterBug (SpoolSample) — MS-RPRN spooler coerce
  - DFSCoerce — MS-DFSNM coerce, often unpatched
  - ShadowCoerce — MS-FSRVP volume shadow copy coerce
  - WebDAV coerce (PrivExchange-style) — HTTP-based NTLM coerce
  - WSUS coerce — abuse update server auth flows
  - Certifried-style coerce + ADCS — chain to domain admin
  - MS-EVEN6 / MS-EFSR / MS-RPRN — various RPC-based coerces

  ### Relay Attacks

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

  ### Kerberos Attacks

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

  ### Delegation Abuse

  - Unconstrained Delegation (TRUSTED_FOR_DELEGATION) — capture TGTs of inbound auths, coerce DC
  - Constrained Delegation (S4U2proxy) — abuse SPN list for service impersonation
  - Protocol Transition (S4U2self) — request ticket as any user without their creds
  - Resource-Based Constrained Delegation (RBCD) — write msDS-AllowedToActOnBehalfOfOtherIdentity, S4U full DA on
  target
  - Machine account quota abuse (MAQ=10) — create computer, set RBCD, take over host
  - Delegation chain abuse — link CD/RBCD across hosts

  ### ACL / ACE Abuse

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

  ### Shadow Credentials

  - msDS-KeyCredentialLink abuse — Whisker/pyWhisker add cert, PKINIT auth → NT hash via UnPAC

  ### ADCS (Certificate Services)

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

  ### Group Policy Attacks

  - GPO modification — write to gPCFileSysPath in SYSVOL
  - SharpGPOAbuse — add scheduled task / immediate task / rights
  - GPP cpassword (legacy) — Groups.xml decrypt
  - MSI/Software Installation GPO — push malicious MSI
  - Logon/Startup script abuse

  ### Trust Attacks

  - SID History injection — golden ticket with foreign SID for cross-domain DA
  - Inter-Forest TGT (printer bug across trust) — coerce trust DC
  - SID filtering bypass — quarantine flag misconfig
  - Trust key extraction — forge inter-realm TGT
  - Foreign Security Principal abuse
  - Cross-forest Kerberoast
  - AzureAD Connect / PHS sync abuse — MSOL account password → DCSync

  ### Lateral Movement

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

  ### Persistence

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

  ### Misc / Modern

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


  ### WSUS Attacks

  - WSUS HTTP (no TLS) — MITM update channel, inject signed PsExec.exe + cmdline → SYSTEM
  - PyWSUS / WSUSpect — replay legitimate Microsoft-signed binaries with malicious args
  - WSUSpendu — push fake update to all clients via DB write on WSUS server
  - SCCM/WSUS shared SQL — abuse SUSDB write access for update injection
  - WSUS server compromise → domain-wide RCE — every client pulls "update"
  - CVE-2025-59287 WSUS RCE — deserialization in AuthorizationCookie, unauth SYSTEM
  - WSUS NAA cred extract — Network Access Account credentials in WMI/registry
  - Group Policy WSUS redirect — write WUServer/WUStatusServer reg keys via GPO
  - Local WSUS hijack — write HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate for self-update poison
  - Autopatch/Intune coexist abuse — MDM channel takeover

  ### SCCM / MECM

  - TAKEOVER-1 to TAKEOVER-9 — SCCM hierarchy privesc chains (SpecterOps research)
  - NAA credential extract — CCM_NetworkAccessAccount blob, DPAPI decrypt → domain creds
  - PXE boot media password crack — extract task sequence policy, AES decrypt
  - Client push installation relay — coerce site server, NTLM relay to MSSQL/SMB
  - Site database access — RBAC_Admins table, grant Full Admin role
  - Application deployment abuse — push package as SYSTEM to all clients
  - Distribution Point access — anonymous SMB share, content extraction
  - AdminService API abuse — REST endpoint on SMS Provider for cmd exec
  - CMPivot RCE — query language abuse for arbitrary script
  - Management Point relay — CCM_HTTPHANDLER coerce → relay

  ### EntraID / Azure AD

  - Device Code phishing — /devicecode endpoint, send code via email/Teams, victim grants
  - Illicit Consent Grant (OAuth phish) — malicious app, victim approves, refresh token stolen
  - Token theft via TokenTactics / ROADtools — refresh token replay, FOCI family abuse
  - Family of Client IDs (FOCI) — exchange token between Microsoft first-party apps (Teams→Graph→Outlook)
  - Primary Refresh Token (PRT) extraction — Mimikatz cloudap, dpapi::cloudapkd
  - PRT cookie forge (x-ms-RefreshTokenCredential) — SSO bypass, browser session
  - Seamless SSO Silver Ticket — AZUREADSSOACC$ NT hash → forge TGS for aadg.windows.net.nsatc.net
  - PHS abuse (Pass-through hash sync) — MSOL_xxx account → DCSync on-prem
  - PTA agent compromise — Azure AD Connect Authentication Agent → cleartext logon capture
  - AD Connect server (Tier 0) — extract MSOL credentials from ADSync DB (DPAPI key in registry)
  - Federation server (ADFS) golden SAML — token-signing cert export → forge any user assertion
  - Cross-tenant access policy abuse — guest invite, resource access
  - Conditional Access bypass — legacy auth (IMAP/POP/SMTP basic), device code, browser bypass
  - MFA fatigue / push bombing — repeat prompts until approval
  - MFA SIM swap / TOTP seed steal
  - Authenticator app session token replay — extract from device
  - AzureHound — graph-based attack path mapping
  - Service Principal abuse — stale SP with high perms, cert/secret reuse
  - App registration owner abuse — add own credentials to existing app
  - Application admin / Cloud App admin — add secrets to any non-privileged SP
  - Privileged Auth Admin / User Admin — reset Global Admin password (legacy)
  - Hybrid Identity Admin — modify sync, push creds
  - Directory Sync Account (Sync_*) — replicate hashes, hidden role
  - Partner relationship (GDAP/DAP) — CSP tenant takeover via partner compromise
  - Managed Identity token abuse — IMDS (169.254.169.254) on Azure VM → token → resource pivot
  - Storage account key / SAS token leak — keyvault/config exposure
  - Key Vault access policy / RBAC abuse — secret read → SP cred → escalation
  - Azure RBAC privesc — Owner/User Access Administrator on subscription
  - Custom role with */write — sneaky perms
  - Run Command / RunCommandManagedDisk — exec on VM via control plane
  - Automation Account / Runbook — RunAs cert export → privesc
  - Logic App / Function App connection abuse
  - Conditional Access policy modification — disable MFA for attacker
  - Cross-tenant synchronization abuse — invite as External Identity → privileged in target
  - Temporary Access Pass (TAP) abuse — User Admin issues TAP for victim
  - Authentication method tampering — register attacker FIDO2/phone for victim
  - BPRT (Bulk Provisioning Token) — register rogue devices, get PRT
  - Workplace Join / Device Registration abuse — fake device, get PRT
  - Intune script push — Win32 app or PowerShell script → SYSTEM on managed endpoints
  - Intune MDM enrollment abuse — admin role pushes config profile with cert
  - Microsoft Graph abuse — Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All SP
  - Exchange Online application access policy bypass
  - Power Platform / Dataverse privilege flaws
  - B2B / B2C tenant pivot
  - Continuous Access Evaluation (CAE) bypass — token replay before revocation propagates

  ### Cross-Cloud / Hybrid Pivots

  - AAD Connect cloud sync → on-prem DCSync (and reverse)
  - Pass-through agent → cleartext password capture via DLL injection
  - Federation cert theft → forge SAML for any cloud app
  - Privileged Identity Management (PIM) eligible role activation race
  - Break-glass account credential reuse

  ### Defense Evasion — Process / Memory

  - AMSI bypass — patch AmsiScanBuffer in amsi.dll (E_INVALIDARG return)
  - AMSI provider unregistration — registry HKLM\Software\Microsoft\AMSI\Providers
  - AMSI hardware breakpoint bypass — Vectored Exception Handler
  - ETW patching — EtwEventWrite / NtTraceEvent ret 0
  - ETW-TI bypass — Threat Intelligence provider
  - PPL bypass — driver load (PPLKiller, RTCore64, gdrv.sys BYOVD)
  - PPLFault / PPLDump — ProcessSnapshot abuse for LSASS dump
  - Direct syscalls (Hell's Gate, Halo's Gate, Tartarus) — skip ntdll user-land hooks
  - Indirect syscalls (SysWhispers3) — return into ntdll syscall instruction for stack legitimacy
  - Unhooking ntdll — fresh copy from disk / KnownDlls / suspended process
  - Module stomping — load benign DLL, overwrite .text with shellcode
  - Module shifting / hollowing
  - Process hollowing (RunPE)
  - Process Doppelgänging (TxF transactions)
  - Process Herpaderping — modify file after section creation
  - Process Ghosting — delete-pending file backed section
  - Transacted Hollowing
  - PoolParty (8 variants) — thread pool injection
  - EarlyCascade / EarlyBird APC injection
  - NtMapViewOfSection cross-process injection
  - DLL sideloading — drop legit signed exe + malicious DLL beside it
  - Phantom DLL hijack — exploit missing DLL load path
  - COM hijacking — HKCU\Software\Classes\CLSID\{...} redirect
  - AppInit_DLLs / AppCertDLLs / Image File Execution Options (legacy)
  - KernelCallbackTable hijack
  - Thread Name-Calling injection (SetThreadDescription)

  ### Defense Evasion — Loader / Payload

  - Reflective DLL injection (Stephen Fewer)
  - sRDI — shellcode RDI conversion
  - Donut — PE/.NET → position-independent shellcode
  - PE2SHC, ScareCrow — encrypted, signed loaders
  - NimPlant / NimCrypt / Nim-RustLoader — uncommon language tradecraft
  - C# .NET assembly load in-memory — Assembly.Load(byte[]), execute-assembly
  - BOF (Beacon Object File) — in-process, no fork-and-run
  - Inline-EA / inline-execute — Cobalt Strike postex without spawning
  - Fork & run replacement — sacrificial process via ppid_spoof + blockdlls
  - PPID spoofing — UpdateProcThreadAttribute PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
  - Block non-MS DLLs — PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
  - CIG (Code Integrity Guard)
  - ACG abuse / bypass for shellcode
  - Stack spoofing (CallStackMasker, SilentMoonwalk) — fake call stack to bypass EDR thread inspection
  - Sleep obfuscation (Ekko, Foliage, Zilean, DeathSleep, MutationGate) — encrypt heap during sleep, ROP wakeup
  - Heap encryption (Ekko ROP chain via timer queue)
  - TimerQueue ROP for sleep masking
  - Sleep with hardware breakpoint masking
  - Hardware Breakpoint hooking (no IAT/inline) — bypass userland EDR
  - Vectored Exception Handler (VEH) abuse

  ### EDR Bypass / Killing

  - BYOVD (Bring Your Own Vulnerable Driver) — RTCore64.sys, gdrv.sys, dbutil.sys, procexp152.sys arbitrary RW kernel
  - EDRSandblast — disable kernel callbacks via vulnerable driver
  - Backstab / Blackout — kill PPL EDR via vuln driver
  - Terminator — Zemana driver kill
  - Spyboy / KillEDR family
  - EDRKillShifter (RansomHub)
  - Kernel callback removal — PsSetCreateProcessNotifyRoutine patch
  - Minifilter altitude unload — detach EDR file callbacks
  - Object callback patch — PsProcessType->CallbackList
  - WMI subscription removal — EDR persistence cleanup
  - EDR DLL unhooking via fresh ntdll
  - Suspending EDR threads — token-impersonation + suspend
  - Driver signature enforcement bypass via testsigning / DSE off via vuln driver
  - NtSetSystemEnvironmentValueEx UEFI tamper (research)
  - PG (PatchGuard) trick suspend / DSEFix-style
  - Telemetry pipeline starvation — fill ETW logger buffer
  - MpCmdRun.exe abuse — Defender LOLBIN, exclude paths via tampering tokens

  ### AV / Defender Specific

  - Defender exclusion via TrustedInstaller token — runas /trustlevel, modify Defender prefs
  - MpPreference tamper — requires SYSTEM + tamper protection off
  - DisableAntiSpyware reg (legacy)
  - MpClient.dll / MpEngine.dll DoS / crash via crafted file
  - Kaspersky / CrowdStrike / SentinelOne / Carbon Black driver-specific bypasses
  - Trend Micro Apex tamper bypass
  - Cylance ML model poisoning (cylance-bypass) — append benign strings/PE sections
  - AV emulator escape — sleep skip detection, env keying

  ### OPSEC / Beacon Drop Without Trip

  - Stageless payload — avoid stage HTTP fetch (signature-rich)
  - HTTPS C2 with valid cert + jitter + sleep ≥ 60s + Malleable C2 profile matching real product UA
  - Domain fronting / redirector chains (CDN77, Cloudflare, Fastly with origin pull)
  - CloudFront / Azure Front Door redirector
  - Legitimate cloud C2 (Slack, Discord, Telegram, Teams, Notion, Trello, Dropbox, OneDrive, GitHub Gists) — covert via
   API
  - DNS over HTTPS C2 (DoH)
  - gRPC / WebSocket C2 in modern app traffic
  - Encrypted shellcode + per-host key derivation (env keying — domain SID, hostname, MAC)
  - GargoyleBypass / Gargoyle — non-executable shellcode at rest, exec via APC
  - Phantom V2 / Cobalt Strike Sleep mask kit + RW→RX→RW cycling
  - Kaspersky/Defender YARA evasion — randomize import names, strings, entropy padding
  - Entropy reduction — base64 strings, fake metadata, signed timestamps
  - Authenticode signed loader — stolen / EV / Microsoft cross-signed cert
  - Signed ATTRIB executable / signed Microsoft binary as loader (LOLBin chain)
  - Living Off The Land Binaries (LOLBAS) — regsvr32, mshta, installutil, msbuild, wmic, cmstp, pcalua, forfiles,
  dfsvc, dnscmd
  - Office payloads — VBA stomping, remote template injection, XLL, Excel 4.0 macros (legacy), MSI, OneNote .one HTA,
  LNK + ISO container (HTML smuggling delivery)
  - HTML smuggling — JS Blob → ISO/IMG/VHD bypassing MOTW
  - Container format MOTW bypass — ISO/IMG/VHDX evade Mark-of-the-Web (CVE-2022-41091 etc)
  - MotW stripping — extract via 7zip pre-2023, etc.
  - Stealthy persistence — COM hijack, registered task with hidden flag, WMI eventfilter, BITS jobs, scheduled task
  with /SD and SDDL hide

  ### Initial Access Stealth

  - OneDrive / SharePoint phish (trusted domain)
  - OAuth illicit consent (token persistence, no creds touched)
  - Browser-in-the-Browser phish
  - Adversary-in-the-Middle (Evilginx, Modlishka, Muraena) — capture session cookies, MFA bypass
  - Tycoon 2FA / Mamba 2FA / EvilProxy PhaaS
  - QR phishing (Quishing) — out-of-band MFA bypass
  - MFA fatigue + Teams/SMS pretext
  - Search engine ads (malvertising) — typosquat installer
  - Chrome extension delivery via stolen dev account
  - NPM / PyPI dependency confusion for build-time RCE on dev machines

  ### Lateral Movement Stealth

  - WMI Event Subscription — fileless persistence + lateral
  - DCOM lateral exec — MMC20.Application, ShellWindows
  - WinRM with -Authentication Negotiate — looks like admin tooling
  - PsExec via custom service name + signed binary
  - SMB named pipe C2 (peer-to-peer beacons) — single egress
  - TCP-only beacon over RDP virtual channel
  - Remote registry + scheduled task XML drop

  ### Anti-Forensics / Log Tamper

  - EventLog clearing → suspicious; instead use ETW provider unregister + targeted log thread suspend
  - Phant0m / EventCleaner — kill Eventlog service threads
  - USN journal delete (fsutil usn deletejournal)
  - Prefetch wipe
  - Timestomping (SetFileTime)
  - Sysmon driver unload via vuln driver
  - WEF/WEC subscription poison
  - PowerShell ScriptBlock logging bypass — [Ref].Assembly.GetType('System.Management.Automation.ScriptBlock').GetField
  ('signatures','NonPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
  - PSReadLine history clear (ConsoleHost_history.txt)
  - Module logging / Transcription disable via reg + group policy override

  ### Misc Modern

  - CLR loader (assembly load via PowerShell-less host)
  - JScript / VBScript host (cscript) for old-school exec
  - MSIX / AppX malicious installers
  - App-V / ClickOnce delivery
  - InstallerFileTakeOver / FilesystemRedirect privesc tricks
  - WSL abuse — Linux subsystem to evade Windows EDR view
  - WSA (Windows Subsystem for Android) abuse
  - Hyper-V VM escape research / nested guest staging
  - Container breakout on Windows containers (silo escape)
  - Speculative side channels for cred extraction (research)

  ### Bonus Niche

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
