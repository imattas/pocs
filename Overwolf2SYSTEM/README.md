# Overwolf2SYSTEM

**Asset:** Overwolf (`OverwolfUpdater` Windows Service)  
**Affected Version:** 0.304.0.11  
**Severity:** High (CVSS score not established)  
**CVSS:** Not assessed  
**Weakness:** CWE-347: Improper Verification of Cryptographic Signature; CWE-863: Incorrect Authorization  
**CVE:** Not Assigned

## Summary

Overwolf 0.304.0.11 contains a local privilege escalation vulnerability in its `OverwolfUpdater` Windows service, which runs as `NT AUTHORITY\SYSTEM`.

The service grants the `Everyone` security principal permission to start it with user-controlled arguments. Its `/InstallCR` functionality accepts an executable path and checks whether the file's signing certificate has an expected Overwolf Subject name without performing full Authenticode signature or certificate-chain validation.

Because certificate Subject names alone do not establish authenticity, an untrusted executable can pass this validation. The service subsequently launches the accepted executable with SYSTEM privileges, allowing a standard local user to cross the Windows privilege boundary.

## Steps to Reproduce

1. Install Overwolf 0.304.0.11 on a Windows 11 test system with the `OverwolfUpdater` service enabled.
2. From a standard user account, verify that the service permissions allow non-administrative users to start the service.
3. Inspect the `FileUtils.FileSignedByOverwolf()` implementation and confirm that the default verification path does not invoke `WinVerifyTrust` and relies on certificate Subject matching.
4. Review the `/InstallCR` handler to confirm that it passes the accepted executable path to `Process.Start()` within the privileged service.
5. In an isolated test environment, use the accompanying PoC to validate the reported privilege-boundary failure and inspect its identity-check output.

**Observed Result:** The supplied reproduction log records successful execution as `nt authority\system` at System integrity, including SYSTEM token privileges such as `SeDebugPrivilege` and `SeImpersonatePrivilege`.

## Affected Code

- `OverwolfUpdater` - Its service security descriptor grants `Everyone` service-start permissions, exposing privileged service functionality to standard users.
- `FileUtils.FileSignedByOverwolf()` - Uses certificate Subject matching without requiring Authenticode signature and trust-chain verification.
- `HandleInstallCR()` - Accepts an executable path from service arguments and launches the accepted file through `Process.Start()` under the service's SYSTEM security context.

## Preconditions and Limitations

Exploitation requires Overwolf 0.304.0.11 and its `OverwolfUpdater` service to be installed on a Windows system. The attacker must already have local code execution as a standard user but does not require administrative privileges.

The vulnerable behavior depends on permissive service-start permissions, insufficient certificate authentication, and execution of a user-selected file by the privileged service.

The finding was confirmed on Windows 11 with Overwolf 0.304.0.11. Other releases were not independently assessed, so the vulnerability should not be assumed to affect every Overwolf version.

The supplied PoC documentation includes a SYSTEM identity proof and describes an additional interactive command-prompt payload. The original execution log confirms SYSTEM execution; the later interactive payload behavior is documented but not independently established by that original log.

The source report identifies the vulnerability as patched but does not provide the exact fixed version.

## Impact

A standard local user can escalate privileges to `NT AUTHORITY\SYSTEM` by exploiting the updater service's insufficient authorization and signature validation.

Successful exploitation permits execution of attacker-controlled code with the privileges of the LocalSystem account, potentially compromising the confidentiality, integrity, and availability of the affected Windows installation.

The supplied reproduction evidence confirms SYSTEM-level execution on the assessed version. The vulnerability is local and does not independently provide remote access.

## References

- [Overwolf Official Website](https://www.overwolf.com/)
- [Overwolf2SYSTEM Proof of Concept](./exploit.ps1)
- [PoC Payload Source](./payload.cs)
