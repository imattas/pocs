# iCUE2SYSTEM

**Asset:** Corsair iCUE 5 (`iCUEUpdateService`)  
**Affected Version:** 5.52.93 (Service: 5.52.93.0)  
**Severity:** High (7.8)  
**CVSS:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`  
**Weakness:** CWE-863: Incorrect Authorization; CWE-829: Inclusion of Functionality from Untrusted Control Sphere  
**CVE:** Not Assigned

## Summary

Corsair iCUE 5.52.93 contains a local privilege escalation vulnerability in its update service. The service authenticates clients based on their executable path rather than their security identity and accepts a caller-controlled package root containing untrusted package metadata.

A standard local user can execute code within their non-elevated iCUE process, satisfy the service's path-based client validation, and supply modified package metadata to the privileged package manager. This allows user-controlled package actions to execute under `NT AUTHORITY\SYSTEM`, crossing the Windows privilege boundary.

## Steps to Reproduce

1. Install Corsair iCUE 5.52.93 with `iCUEUpdateService` enabled.
2. Run the included PoC from a standard, non-administrative Windows account.
3. The PoC communicates with the update service through its local Qt Remote Objects endpoint and uses a private copy of package metadata to demonstrate the authorization flaw.
4. Observe the resulting identity-check output produced by the privileged service.

**Observed Result:** The PoC successfully executed its fixed identity-check command as `NT AUTHORITY\SYSTEM` (SID `S-1-5-18`) at System Mandatory Level.

## Affected Code

* `iCUEUpdateService` - Validates connecting clients using their executable path without adequately verifying the caller's security identity or authorization.
* Privileged package manager - Accepts a caller-selected package root and processes user-controlled package metadata within a SYSTEM-level service.

## Preconditions and Limitations

Exploitation requires Corsair iCUE 5.52.93 and its update service to be installed and running. An attacker must already possess the ability to execute code locally as a standard Windows user.

The vulnerability depends on the service accepting requests from a user-controlled iCUE process and subsequently processing package metadata from a user-writable location.

The PoC was verified locally on October 25, 2026, using a private copy of the package registry. The installed registry remained unchanged during testing.

Only iCUE 5.52.93 was assessed. Earlier and later versions were not tested, and the PoC does not demonstrate remote exploitation or exploitation without a local user account.

## Impact

A standard local user can cross the Windows privilege boundary and execute a command with `NT AUTHORITY\SYSTEM` privileges through the iCUE update service.

The demonstrated impact is local privilege escalation from a non-administrative account to SYSTEM integrity. This compromises the separation between ordinary user processes and privileged Windows services.

The PoC confirms execution of a fixed identity-check command at SYSTEM integrity. Broader arbitrary command execution was not independently established by this specific demonstration.

## References

* [iCUE2SYSTEM Proof of Concept](./poc.cpp)
* [Corsair Official Website](https://www.corsair.com/)
