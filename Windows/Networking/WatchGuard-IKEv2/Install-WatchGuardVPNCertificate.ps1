#Requires -Version 5.1
# NinjaOne: Run as SYSTEM. Reads organization custom fields and always refreshes the staged VPN JSON.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$LogDirectory = Join-Path $env:ProgramData 'AUT\Logs'
$LogPath = Join-Path $LogDirectory 'WatchGuardVPN-Deployment.log'
$ConfigDirectory = Join-Path $env:ProgramData 'AUT\VPN'
$ConfigPath = Join-Path $ConfigDirectory 'WatchGuardVPN.json'

function Write-DeploymentLog {
    param([ValidateSet('INFO','WARN','ERROR')][string]$Level, [string]$Message)
    $line = '{0} [{1}] [SYSTEM] [Certificate] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,$Message
    Write-Output $line
    if (-not (Test-Path -LiteralPath $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}
function Get-RequiredNinjaField {
    param([string]$Name,[string]$Type='Text')
    if (-not (Get-Command Get-NinjaProperty -ErrorAction SilentlyContinue)) { throw 'Get-NinjaProperty is unavailable. Run this automation as SYSTEM in NinjaOne.' }
    $value = Get-NinjaProperty -Name $Name -Type $Type -ErrorAction Stop
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { throw "NinjaOne custom field '$Name' is missing or empty." }
    if ($value -is [array]) { return ($value -join [Environment]::NewLine) }
    return [string]$value
}
function Assert-Hostname {
    param([string]$Value,[string]$Field)
    if ($Value.Length -gt 253 -or $Value -notmatch '^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$') { throw "Invalid $Field value." }
}
function Get-VpnRoutes {
    param([string]$Raw)
    $routes = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in ($Raw -split '[\r\n,;]+')) {
        $prefix = $line.Trim()
        if (-not $prefix) { continue }
        $parts = $prefix.Split('/')
        if ($parts.Count -ne 2 -or $parts[1] -notmatch '^\d{1,3}$') { throw "Invalid VPN CIDR prefix: '$prefix'." }
        $addr = $null
        if (-not [System.Net.IPAddress]::TryParse($parts[0],[ref]$addr)) { throw "Invalid VPN CIDR address: '$prefix'." }
        $bits = if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
        if ([int]$parts[1] -gt $bits) { throw "Invalid VPN CIDR mask: '$prefix'." }
        $normalized = '{0}/{1}' -f $addr.IPAddressToString,[int]$parts[1]
        if (-not $routes.Contains($normalized)) { $routes.Add($normalized) }
    }
    if ($routes.Count -eq 0) { throw 'VPNRoutes must specify at least one CIDR prefix.' }
    return ,$routes.ToArray()
}
function Set-SecureConfigDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    # Use well-known SIDs to remain compatible with localized Windows installations.
    # SYSTEM and built-in Administrators: full control; built-in Users: read and execute.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($entry in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@('S-1-5-32-545','ReadAndExecute'))) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($entry[0])
        $rights = [System.Security.AccessControl.FileSystemRights]$entry[1]
        $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$rights,$inherit,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Set-SecureConfigFile {
    param([string]$Path)
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($entry in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@('S-1-5-32-545','ReadAndExecute'))) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($entry[0])
        $rights = [System.Security.AccessControl.FileSystemRights]$entry[1]
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$rights,[System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
try {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'This script must run as LOCAL SYSTEM.' }
    Write-DeploymentLog INFO 'Started certificate installation and VPN configuration staging.'
    # Read every required field before changing the trust store or overwriting prior configuration.
    $name = (Get-RequiredNinjaField 'VPNName').Trim()
    $server = (Get-RequiredNinjaField 'VPNServer').Trim()
    $dnsSuffix = (Get-RequiredNinjaField 'VPNDnsSuffix').Trim()
    $routes = @(Get-VpnRoutes -Raw (Get-RequiredNinjaField 'VPNRoutes' 'Multiline'))
    $raw = Get-RequiredNinjaField 'VPNCertBase64' 'Multiline'
    if ($name.Length -gt 128 -or $name -match '[\x00-\x1f]' -or $name.Length -eq 0) { throw 'Invalid VPNName.' }
    Assert-Hostname $server 'VPNServer'
    Assert-Hostname $dnsSuffix 'VPNDnsSuffix'
    $base64 = $raw -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','' -replace '\s',''
    $bytes = [Convert]::FromBase64String($base64)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)
    if ((Get-Date) -lt $cert.NotBefore -or (Get-Date) -gt $cert.NotAfter) { throw 'CA certificate is expired or not yet valid.' }
    $basic = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
    if (-not $basic -or -not $basic.CertificateAuthority) { throw 'Certificate does not have CA basic constraints.' }
    if ($cert.Subject -ne $cert.Issuer) { throw 'Certificate is not self-issued. Review its trust-store placement.' }
    $thumbprint = $cert.Thumbprint
    Write-DeploymentLog INFO "Validated WatchGuard CA certificate (thumbprint: $thumbprint). Ensure the source is the trusted Firebox export."
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $found = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$thumbprint,$false)
        if ($found.Count -eq 0) {
            $store.Add($cert)
            Write-DeploymentLog INFO "Imported CA certificate (thumbprint: $thumbprint)."
        } else { Write-DeploymentLog INFO "CA certificate already installed (thumbprint: $thumbprint)." }
        $found = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$thumbprint,$false)
        if ($found.Count -eq 0) { throw 'Certificate import verification failed.' }
    } finally { $store.Close() }

    # Always refresh the non-secret configuration, even if the certificate was already installed.
    $config = [ordered]@{ SchemaVersion=1; VPNName=$name; VPNServer=$server; VPNDnsSuffix=$dnsSuffix; VPNRoutes=@($routes); VPNCertThumbprint=$thumbprint }
    $json = $config | ConvertTo-Json -Depth 4
    Set-SecureConfigDirectory $ConfigDirectory
    $tempPath = Join-Path $ConfigDirectory ([guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [System.IO.File]::WriteAllText($tempPath,$json,(New-Object System.Text.UTF8Encoding($false)))
        Set-SecureConfigFile $tempPath
        # Same-volume rename replaces the existing config without offering users a writable staging file.
        if (Test-Path -LiteralPath $ConfigPath) {
            $backup = Join-Path $ConfigDirectory ([guid]::NewGuid().ToString('N') + '.bak')
            try { [System.IO.File]::Replace($tempPath,$ConfigPath,$backup,$true) }
            finally { if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force } }
        } else { [System.IO.File]::Move($tempPath,$ConfigPath) }
        Set-SecureConfigFile $ConfigPath
    } finally { if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force } }
    Write-DeploymentLog INFO "Refreshed staged VPN configuration: $ConfigPath (VPN: '$name', routes: $($routes.Count))."
    Write-DeploymentLog INFO 'Certificate deployment and configuration staging successful.'
    exit 0
} catch {
    try { Write-DeploymentLog ERROR $_.Exception.Message } catch { Write-Error $_.Exception.Message }
    exit 1
}
