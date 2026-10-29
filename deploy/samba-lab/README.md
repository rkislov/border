# Samba AD laboratory

This image supplies Samba AD and winbind only; no FreeRADIUS is installed.
The deployed laboratory was verified with MikroTik CHR on 2026-10-29.
See ../../docs/MIKROTIK-UTM.md. These files are supporting lab components,
not a complete automated production installer.
Do not expose the domain controller's ports to the public Internet.

Border's host administrator selects `BORDER_NTLM_AUTH` (an absolute executable
path implementing `ntlm_auth --helper-protocol=ntlm-server-1`). Domain admins
select only the NetBIOS domain, never a command or executable path.

MS-CHAPv2 currently targets SSH. TOTP, EAP and VPN/MPPE are not supported by this
path. LDAP account state must be available; an outage denies new access.
