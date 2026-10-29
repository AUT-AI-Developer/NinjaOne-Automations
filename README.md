# NinjaOne Automations

Reusable, customer-neutral PowerShell automations for NinjaOne RMM.

## Automations

- [WatchGuard IKEv2 VPN](Windows/Networking/WatchGuard-IKEv2/README.md) — installs a trusted CA certificate as SYSTEM and configures a per-user VPN profile in the Current User context.

## Security and deployment

This is a **public** source repository. Never commit customer names, domains, VPN endpoints, IP ranges, exported certificates, credentials, tokens, customer device information, logs, or generated configuration files. Replace all examples with neutral placeholders.

Review scripts and test them on a nonproduction endpoint before deployment. Copy the vetted script versions into the NinjaOne Automation Library; do not automatically execute unreviewed repository branches on customer devices.

## Status

The WatchGuard VPN scripts were validated in a live endpoint deployment and connectivity test on October 29, 2026. That validation does not establish compatibility with every Windows or Firebox configuration.
