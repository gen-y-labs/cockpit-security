/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import cockpit from "cockpit";

import type {
    SecurityFinding,
    SecurityProvider,
    SecurityReport,
    SecuritySeverity,
    SecuritySummary,
} from '../security-report';

interface TrivyVulnerability {
    VulnerabilityID?: string;
    PkgName?: string;
    InstalledVersion?: string;
    FixedVersion?: string;
    Title?: string;
    Description?: string;
    Severity?: string;
    Status?: string;
}

interface TrivyResult {
    Vulnerabilities?: TrivyVulnerability[];
}

interface TrivyOutput {
    Results?: TrivyResult[];
}

let cachedReport: SecurityReport | null = null;
const TRIVY_BINARY = "/usr/bin/trivy";
export const TRIVY_INSTALL_URL = "https://trivy.dev/docs/latest/getting-started/installation/";

function normalizeSeverity(value: string | undefined): SecuritySeverity {
    const severity = (value || "").toLowerCase();

    if (severity === "critical")
        return "critical";
    if (severity === "high")
        return "high";
    if (severity === "medium")
        return "medium";
    if (severity === "low")
        return "low";

    return "unknown";
}

function createSummary(findings: SecurityFinding[]): SecuritySummary {
    const summary: SecuritySummary = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
        total: findings.length,
    };

    for (const finding of findings)
        summary[finding.severity] += 1;

    return summary;
}

function createSummaryText(vulnerability: TrivyVulnerability): string {
    const title = vulnerability.Title || vulnerability.Description || cockpit.gettext("No description");
    const packageName = vulnerability.PkgName || cockpit.gettext("unknown-package");
    const installed = vulnerability.InstalledVersion || "";
    const fixed = vulnerability.FixedVersion || "";

    if (installed && fixed)
        return cockpit.format(_("$0 ($1 -> $2)"), title, `${packageName} ${installed}`, fixed);
    if (installed)
        return cockpit.format(_("$0 ($1)"), title, `${packageName} ${installed}`);

    return cockpit.format(_("$0 ($1)"), title, packageName);
}

function parseTrivyOutput(output: string): SecurityFinding[] {
    let parsed: TrivyOutput;
    try {
        parsed = JSON.parse(output) as TrivyOutput;
    } catch (error) {
        throw new Error(cockpit.format(_("Failed to parse Trivy JSON output: $0"), error instanceof Error ? error.message : String(error)));
    }

    const findings: SecurityFinding[] = [];
    const results = parsed.Results || [];

    for (const result of results) {
        for (const vulnerability of result.Vulnerabilities || []) {
            const vulnerabilityId = vulnerability.VulnerabilityID || cockpit.gettext("unknown-id");
            const packageName = vulnerability.PkgName || cockpit.gettext("unknown-package");

            findings.push({
                id: `${vulnerabilityId}-${packageName}-${findings.length + 1}`,
                summary: createSummaryText(vulnerability),
                severity: normalizeSeverity(vulnerability.Severity),
                status: vulnerability.Status || "affected",
                source: "trivy",
            });
        }
    }

    return findings;
}

function formatSpawnError(error: unknown): string {
    const installHint = cockpit.format(
        _("Trivy is not installed on this system. Install Trivy with your package manager. Installation guide: $0"),
        TRIVY_INSTALL_URL
    );

    if (typeof error === "string")
        return error.toLowerCase().includes("not-found") ? installHint : error;
    if (error && typeof error === "object" && "problem" in error && error.problem === "not-found")
        return installHint;
    if (error && typeof error === "object" && "exit_status" in error && error.exit_status === 127)
        return installHint;
    if (error && typeof error === "object" && "message" in error && typeof error.message === "string") {
        const message = error.message;
        const normalized = message.toLowerCase();
        if (normalized.includes("not-found") ||
            normalized.includes("no such file or directory") ||
            normalized.includes("command not found")) {
            return installHint;
        }

        return message;
    }

    return cockpit.gettext("Unknown command error");
}

const _ = cockpit.gettext;

function getTrivyCommand(): string[] {
    return [
        TRIVY_BINARY,
        "fs",
        "--format",
        "json",
        "--quiet",
        "/",
    ];
}

export class TrivyProvider implements SecurityProvider {
    async getReport(): Promise<SecurityReport> {
        const output = await cockpit.spawn(getTrivyCommand(), { err: "message", environ: ["LC_ALL=C"] })
                .catch(error => Promise.reject(new Error(formatSpawnError(error))));

        const findings = parseTrivyOutput(output.toString());
        const report: SecurityReport = {
            provider: "trivy",
            generatedAt: new Date().toISOString(),
            findings,
            summary: createSummary(findings),
        };

        cachedReport = report;
        return report;
    }
}

export function getCachedTrivyReport(): SecurityReport | null {
    return cachedReport;
}
