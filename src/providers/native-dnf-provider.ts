/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import cockpit from "cockpit";

import { createReportMetadata } from '../report-metadata';
import type {
    SecurityFinding,
    SecurityProvider,
    SecurityReport,
    SecuritySeverity,
    SecuritySummary,
} from '../security-report';

const DNF_COMMAND = ["dnf", "-q", "updateinfo", "list", "updates", "security"];
const DNF_VERSION_COMMAND = ["dnf", "--version"];

function normalizeSeverity(value: string): SecuritySeverity {
    const severity = value.toLowerCase();

    if (severity.includes("critical"))
        return "critical";
    if (severity.includes("important") || severity.includes("high"))
        return "high";
    if (severity.includes("moderate") || severity.includes("medium"))
        return "medium";
    if (severity.includes("low"))
        return "low";

    return "unknown";
}

function createSummary(findings: SecurityFinding[]): SecuritySummary {
    const summary = {
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

function parseDnfOutput(output: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const seen = new Set<string>();

    for (const line of output.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed)
            continue;
        if (trimmed.startsWith("Last metadata expiration check"))
            continue;
        if (trimmed.toLowerCase().startsWith("update id"))
            continue;
        if (trimmed.startsWith("="))
            continue;

        const columns = trimmed.split(/\s+/);
        if (columns.length < 3)
            continue;

        const advisory = columns[0];
        const severityColumn = columns.find(column => column.toLowerCase().includes("/sec")) || columns[1];
        const packageName = columns[columns.length - 1];

        if (!packageName || packageName === advisory)
            continue;

        const id = `${advisory}:${packageName}`;
        if (seen.has(id))
            continue;
        seen.add(id);

        findings.push({
            id,
            summary: trimmed,
            status: "upgradable",
            severity: normalizeSeverity(severityColumn),
            source: "native-dnf",
        });
    }

    return findings;
}

function formatSpawnError(error: unknown): string {
    if (typeof error === "string")
        return error;
    if (error && typeof error === "object" && "message" in error && typeof error.message === "string")
        return error.message;
    return cockpit.gettext("Unknown command error");
}

function parseDnfVersion(output: string): string {
    const firstLine = output.split('\n')
            .map(line => line.trim())
            .find(Boolean) || "";
    if (!firstLine)
        return "unknown";

    return firstLine;
}

export class NativeDnfProvider implements SecurityProvider {
    async getReport(): Promise<SecurityReport> {
        const startedAt = Date.now();
        const output = await cockpit.spawn(DNF_COMMAND, { err: "message", environ: ["LC_ALL=C"] })
                .catch(error => Promise.reject(new Error(formatSpawnError(error))));

        const findings = parseDnfOutput(output.toString());
        const generatedAt = new Date().toISOString();
        const scanSeconds = (Date.now() - startedAt) / 1000;
        const scannerVersionOutput = await cockpit.spawn(DNF_VERSION_COMMAND, { err: "message", environ: ["LC_ALL=C"] }).catch(() => "");
        const metadata = await createReportMetadata({
            generatedAt,
            scanSeconds,
            packageManager: "dnf",
            scannerVersion: parseDnfVersion(scannerVersionOutput.toString()),
            scannerDatasetVersion: "unknown",
        });

        return {
            provider: "native-dnf",
            generatedAt,
            findings,
            summary: createSummary(findings),
            metadata,
        };
    }
}
