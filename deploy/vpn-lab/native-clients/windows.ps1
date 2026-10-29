# Run in elevated Windows PowerShell. No passwords are stored in this script.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CaPath,
    [Parameter(Mandatory=$true)][string]$CaSha256,
    [string]$ServerAddress = '192.168.128.10',
    [string]$Name = 'Border CHR Lab'
)
$ErrorActionPreference = 'Stop'
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Resolve-Path $CaPath).Path)
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $actual = ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-', '') }
finally { $sha.Dispose() }
if ($actual -ne ($CaSha256 -replace '[:\s-]', '')) { throw 'CA SHA256 fingerprint mismatch' }
if ($cert.NotAfter -le (Get-Date)) { throw 'Lab CA expired; regenerate the lab certificates' }
if (Get-VpnConnection -Name $Name -ErrorAction SilentlyContinue) { throw 'VPN name already exists; existing profile was not modified' }
# IKEv2 validates the gateway certificate through the machine certificate store.
Import-Certificate -FilePath $CaPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
$eap = New-EapConfiguration
Add-VpnConnection -Name $Name -ServerAddress $ServerAddress -TunnelType Ikev2 `
    -AuthenticationMethod Eap -EapConfigXmlStream $eap.EapConfigXmlStream `
    -EncryptionLevel Required -SplitTunneling -RememberCredential:$false | Out-Null
Set-VpnConnectionIPsecConfiguration -ConnectionName $Name -AuthenticationTransformConstants SHA256128 `
    -CipherTransformConstants AES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 `
    -DHGroup Group14 -PfsGroup None -Force | Out-Null
Add-VpnConnectionRoute -ConnectionName $Name -DestinationPrefix '10.182.0.1/32' | Out-Null
Write-Host "Profile ready: $Name. Connect through Windows VPN settings with domain-test or local/chr-test."
Write-Host "Test: ping 10.182.0.1. Only the lab /32 is routed through this VPN."
Write-Host "CA thumbprint for later removal: $($cert.Thumbprint)"
