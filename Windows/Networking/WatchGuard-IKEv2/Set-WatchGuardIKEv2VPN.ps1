#Requires -Version 5.1
# NinjaOne execution context: Current User (interactive Windows account)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$MainLogDirectory = Join-Path $env:ProgramData 'AUT\Logs'
$MainLogPath = Join-Path $MainLogDirectory 'WatchGuardVPN-Deployment.log'
$FallbackLogDirectory = Join-Path $env:LOCALAPPDATA 'AUT\Logs'
$FallbackLogPath = Join-Path $FallbackLogDirectory 'WatchGuardVPN-Deployment.log'

function Write-DeploymentLog {
    param([ValidateSet('INFO','WARN','ERROR')][string]$Level,[string]$Message)
    $line = '{0} [{1}] [USER:{2}] [VPN] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,[Security.Principal.WindowsIdentity]::GetCurrent().Name,$Message
    Write-Output $line
    try {
        if (-not (Test-Path -LiteralPath $MainLogDirectory)) { New-Item -Path $MainLogDirectory -ItemType Directory -Force | Out-Null }
        Add-Content -LiteralPath $MainLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # No broad write ACL is granted to standard users. Retain their logs under their own profile.
        if (-not (Test-Path -LiteralPath $FallbackLogDirectory)) { New-Item -Path $FallbackLogDirectory -ItemType Directory -Force | Out-Null }
        Add-Content -LiteralPath $FallbackLogPath -Value $line -Encoding UTF8
    }
}
$ConfigPath = Join-Path $env:ProgramData 'AUT\VPN\WatchGuardVPN.json'
function Get-StagedConfiguration {
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "VPN configuration not staged: $ConfigPath. Run Install-WatchGuardVPNCertificate.ps1 as SYSTEM first."
    }
    $config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if ($config.SchemaVersion -ne 1) { throw 'Unsupported or missing staged VPN configuration version.' }
    foreach ($key in @('VPNName','VPNServer','VPNDnsSuffix','VPNCertThumbprint')) {
        if ([string]::IsNullOrWhiteSpace([string]$config.$key)) { throw "Missing staged VPN value: $key" }
    }
    if (-not $config.VPNRoutes -or @($config.VPNRoutes).Count -eq 0) { throw 'No VPN routes in staged configuration.' }
    return $config
}
try {
    Write-DeploymentLog INFO 'Started user VPN configuration.'
    Import-Module VpnClient -ErrorAction Stop
    $config = Get-StagedConfiguration
    $name = ([string]$config.VPNName).Trim()
    $server = ([string]$config.VPNServer).Trim()
    $dnsSuffix = ([string]$config.VPNDnsSuffix).Trim()
    $routes = @($config.VPNRoutes | ForEach-Object { [string]$_ } | Select-Object -Unique)
    $thumbprint = ([string]$config.VPNCertThumbprint).Trim().ToUpperInvariant()
    if ($name.Length -eq 0 -or $name.Length -gt 128 -or $name -match '[\x00-\x1f]') { throw 'Invalid staged VPNName.' }
    if ($server -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$' -or $server -match '\.\.') { throw 'Invalid staged VPNServer.' }
    if ($dnsSuffix -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$' -or $dnsSuffix -match '\.\.') { throw 'Invalid staged VPNDnsSuffix.' }
    if ($thumbprint -notmatch '^[0-9A-F]{40}$') { throw 'Invalid staged certificate thumbprint.' }
    foreach ($route in $routes) {
        if ($route -notmatch '^[0-9a-fA-F:.]+/\d{1,3}$') { throw "Invalid staged route: $route" }
    }
    $installed = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -ieq $thumbprint } | Select-Object -First 1
    if (-not $installed) { throw "Required CA certificate ($thumbprint) is not installed. Run SYSTEM certificate automation first." }
    if ((Get-Date) -lt $installed.NotBefore -or (Get-Date) -gt $installed.NotAfter) { throw 'Installed VPN CA certificate is outside its validity period.' }
    Write-DeploymentLog INFO "Loaded staged VPN configuration; CA thumbprint $thumbprint verified."
    $vpn = Get-VpnConnection -Name $name -ErrorAction SilentlyContinue
    if (-not $vpn) {
        $add = @{ Name=$name; ServerAddress=$server; TunnelType='Ikev2'; EncryptionLevel='Required'; AuthenticationMethod='Eap'; SplitTunneling=$true; RememberCredential=$true; Force=$true; ErrorAction='Stop' }
        if ($dnsSuffix) { $add.DnsSuffix = $dnsSuffix }
        Add-VpnConnection @add | Out-Null
        Write-DeploymentLog INFO "Created per-user VPN '$name'."
    }
    else {
        if ([string]$vpn.TunnelType -ne 'Ikev2') { throw "Existing VPN '$name' uses a different tunnel type. Refusing destructive replacement." }
        $set = @{ Name=$name; ServerAddress=$server; AuthenticationMethod='Eap'; EncryptionLevel='Required'; SplitTunneling=$true; RememberCredential=$true; Force=$true; ErrorAction='Stop' }
        if ($dnsSuffix) { $set.DnsSuffix = $dnsSuffix }
        Set-VpnConnection @set | Out-Null
        Write-DeploymentLog INFO "Reconciled existing VPN '$name'."
    }
    # Preserve the exact IPsec policy values from the original AddVPN.ps1.
    Set-VpnConnectionIPsecConfiguration -ConnectionName $name -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 -DHGroup Group14 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -PfsGroup None -Force -ErrorAction Stop | Out-Null
    # Windows ships Add-VpnConnectionRoute but no Get-VpnConnectionRoute cmdlet.
    # Attempt each desired route; a confirmed already-exists response is safe to skip.
    # -PassThru verifies successful creation for newly added routes, not runtime reachability.
    foreach ($route in $routes) {
        try {
            $addedRoute = Add-VpnConnectionRoute -ConnectionName $name -DestinationPrefix $route -PassThru -ErrorAction Stop
            if (-not $addedRoute -or -not (@($addedRoute) | Where-Object { $_.DestinationPrefix -eq $route })) {
                throw "VPN route addition returned no matching route for $route."
            }
            Write-DeploymentLog INFO "Added VPN route $route."
        }
        catch {
            $routeError = $_.Exception.Message
            # Avoid hiding access, validation or RPC failures as duplicates.
            if ($routeError -match '(?i)(already exists|already been added|duplicate|already present)') {
                Write-DeploymentLog WARN "VPN route $route appears already present; Windows does not expose Get-VpnConnectionRoute for independent profile-route verification."
            }
            else { throw "Unable to configure VPN route ${route}: $routeError" }
        }
    }
    $result = Get-VpnConnection -Name $name -ErrorAction Stop
    if ($result.ServerAddress -ine $server -or [string]$result.TunnelType -ne 'Ikev2' -or -not $result.SplitTunneling) { throw 'VPN verification failed (server, tunnel type, or split tunneling).' }
    # Get-VpnConnection verifies profile properties but not profile route entries.
    # Route additions are verified using the Add-VpnConnectionRoute -PassThru result;
    # pre-existing routes are accepted only if Windows reports an explicit duplicate.
    Write-DeploymentLog INFO "VPN '$name' configured successfully."
    exit 0
}
catch {
    try { Write-DeploymentLog ERROR $_.Exception.Message } catch { Write-Error $_.Exception.Message }
    exit 1
}
