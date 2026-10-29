# WatchGuard Mobile VPN with IKEv2 — NinjaOne

Two independent PowerShell automations for Windows endpoints.

## Automations

1. **Install-WatchGuardVPNCertificate.ps1** — execute in NinjaOne as **SYSTEM**. Reads organization custom fields, validates a Firebox-exported root CA certificate, imports it directly from memory into `Cert:\LocalMachine\Root` if necessary, and **always** stages the latest non-secret VPN settings at `C:\ProgramData\AUT\VPN\WatchGuardVPN.json`.
2. **Set-WatchGuardIKEv2VPN.ps1** — execute as **Current User** after the SYSTEM automation. Reads the staged JSON (not the protected NinjaOne CLI), verifies the CA, and creates or updates that user's per-user IKEv2 VPN profile and configured routes.

## Required NinjaOne organization custom fields

| Field | Suggested type | Example |
| --- | --- | --- |
| `VPNName` | Text | `Example IKEv2 VPN` |
| `VPNServer` | Text | `vpn.example.com` |
| `VPNDnsSuffix` | Text | `example.com` |
| `VPNRoutes` | Multiline | `192.0.2.0/24` (one prefix per line) |
| `VPNCertBase64` | Multiline | Base64 of a trusted Firebox-exported public CA certificate |

Give NinjaOne scripts permission to read these organization fields. The certificate thumbprint is derived automatically; no `VPNCertThumbprint` field is needed.

## Execution and logging

- Run the SYSTEM stage first, then the Current User stage. For devices without an interactive user, schedule the user stage at the next appropriate user login through NinjaOne.
- The SYSTEM stage logs to `C:\ProgramData\AUT\Logs\WatchGuardVPN-Deployment.log`.
- The user stage attempts the same log, and falls back to `%LOCALAPPDATA%\AUT\Logs\WatchGuardVPN-Deployment.log` if access is denied.
- Windows standard users receive read-only access to `C:\ProgramData\AUT\VPN\WatchGuardVPN.json`; SYSTEM and Administrators retain write access.

## Notes and scope

- Keep customer-specific values and exported CA certificates **only** in the customer's NinjaOne organization configuration. Never commit populated JSON files or certificate exports.
- Preserve/compare each customer's WatchGuard-generated IKEv2 settings when deploying. The current script uses EAP, AES256, GCMAES256 and DH Group14 based on the originally tested profile; these are not universal Firebox defaults.
- Route addition uses `Add-VpnConnectionRoute -PassThru` and handles explicit already-exists responses. Windows does not provide a `Get-VpnConnectionRoute` cmdlet. Existing routes are not independently reconciled and obsolete routes are not removed.
- Verify connection and network reachability on target customers. Tested successfully on one endpoint October 29, 2026; additional environments require their own validation.
- These scripts do not contain VPN credentials or private keys. Public CA certificate imports still change machine trust and must be reviewed.
