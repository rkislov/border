# Native IKEv2 clients for the CHR lab

The lab gateway is RouterOS CHR at `192.168.128.10`. It uses a dedicated,
short-lived CA, server certificate `chr-vpn.lab.border.test` (including the
IP SAN), AES-256/SHA-256/DH14, and EAP-MSCHAPv2 through Border. The client pool
is `10.182.0.10–20`; only `10.182.0.1/32` is included in the tunnel.
The client must have network reachability to the CHR private address (UDP
500/4500 and ESP where NAT-T is not used). This is not a public VPN endpoint.

## Windows — prepared, not yet tested on Windows

Transfer `windows.ps1` and the **public DER CA certificate** to a Windows
machine on the lab network. Obtain its SHA-256 certificate fingerprint over a
trusted channel. Run Windows PowerShell as administrator, using the intended
Windows user's account (the VPN profile is per-user):

```powershell
.\windows.ps1 -CaPath .\chr-vpn-ca.cer -CaSha256 'CERTIFICATE_SHA256'
```

The script checks the certificate fingerprint/expiry, installs the CA into
LocalMachine Root and creates `Border CHR Lab`. It refuses to overwrite an
existing profile. It does not save credentials or enable automatic use of
Windows logon credentials. The IKEv2 layer authenticates the gateway using its
certificate; EAP-MSCHAPv2 authenticates the user.

Connect through Settings → Network & internet → VPN. Use `domain-test` for
Samba or `local/chr-test` for the Border local account. Enter the lab password
at connection time. Test `ping 10.182.0.1`, inspect Border accounting, then
check wrong-password refusal and automatic revocation after blocking the test
user. Re-enable the user after the test. These checks remain pending on Windows.

To remove this lab profile, use `Remove-VpnConnection -Name 'Border CHR Lab'
-Force`. Remove only this lab CA from LocalMachine Root by the thumbprint
printed during installation, and only after all lab profiles using it are removed.

## macOS

Generate a profile containing the public CA and VPN configuration:

```sh
python3 macos.py --ca /path/to/chr-vpn-ca.crt --output /path/to/Border-CHR.mobileconfig
open /path/to/Border-CHR.mobileconfig
```

Review and install it in System Settings → General → Device Management.
Installation adds trust for the dedicated lab CA. The default account is
`domain-test`; `--username local/chr-test` selects the local test account.
No password is embedded. Only the first server-provided split route is used
by macOS, so this lab advertises one `/32`. Verify actual routing and encrypted
traffic after connecting. Remove the profile after lab testing.

## Mixed SSH/VPN NAS

Keep existing SSH bindings and add separate EAP VPN bindings. RouterOS SSH
revocation fallback requires a tracked access grant whose policy is SSH;
the NAS default mode alone is insufficient. VPN grants, unknown grants and
grants belonging to another user/NAS are rejected before any management SSH
connection. This prevents a VPN disconnect failure from selecting a user's
concurrent SSH session.

References: [Microsoft New-EapConfiguration](https://learn.microsoft.com/en-us/powershell/module/vpnclient/new-eapconfiguration),
[Microsoft Add-VpnConnection](https://learn.microsoft.com/en-us/powershell/module/vpnclient/add-vpnconnection),
[Apple IKEv2 payload](https://developer.apple.com/documentation/devicemanagement/vpn/ikev2-data.dictionary),
[RouterOS IPsec](https://help.mikrotik.com/docs/spaces/ROS/pages/11993097/IPsec).

Lab verification on 2026-10-29: CHR 7.23.8 has the IKEv2 peer, certificate,
split pool and RADIUS IPsec service configured. Border has four bindings on
that NAS: local/domain SSH and local/domain EAP VPN. Domain SSH login still
passes after adding VPN bindings. RouterOS adapter/AAA race tests, Go vet and
deployed API health/search/pagination smoke checks pass. Native-client tunnel,
traffic and revocation tests are pending profile installation on macOS and
availability of Windows. Server setup alone does not prove client compatibility.

Linux VM interoperability and CHR fixes are documented in [UTM-CLIENT.md](../UTM-CLIENT.md). Native-client validation remains pending.
