# Security Model

## Scope

Cockpit Security is a read-only visibility plugin. It reports:

- pending security updates (`Updates` tab)
- vulnerability scan results (`Vulnerabilities` tab)
- compliance scan results (`Compliance` tab)

The plugin does not perform package remediation, host hardening changes, or automatic background scans.

## Trust Boundaries

- Browser UI runs in Cockpit frontend context.
- Command execution is performed through Cockpit bridge on the managed host.
- Scanner binaries and host package managers are external trust dependencies.

## Data Sources

- Native package manager output (`zypper`, `apt` simulation mode)
- Trivy JSON output
- OpenSCAP ARF/XML output

Results are normalized into a common report structure for rendering.

## Execution Model

- Scans are user-triggered from UI actions.
- Errors from command execution/parsing are surfaced in the tab.
- No telemetry or external data upload is performed by this plugin.

## Data Handling

- Reports are kept in memory for current session use.
- Users can manually export report JSON.
- No long-term persistence is implemented by default.

## Privilege and Safety Considerations

- Scan completeness depends on host permissions and available scanner content.
- Package manager and scanner commands must exist on target host.
- Compliance scans require valid SCAP content files.

## Non-Goals

- Automatic remediation
- Policy enforcement
- Intrusion prevention
- Endpoint quarantine
