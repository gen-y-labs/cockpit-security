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

const ZYPPER_COMMAND = ["zypper", "-q", "list-patches", "--category", "security"];
const ZYPPER_VERSION_COMMAND = ["zypper", "--version"];

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

function isHeaderRow(columns: string[]): boolean {
    const normalized = columns.map(value => value.toLowerCase());
    return normalized.includes("name") && normalized.includes("severity") && normalized.includes("summary");
}

function parseZypperOutput(output: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const line of output.split('\n')) {
        if (!line.includes('|'))
            continue;
        if (/^[\s+\-|]+$/.test(line))
            continue;

        const columns = line.split('|').map(value => value.trim());
        if (columns.length < 6 || isHeaderRow(columns))
            continue;

        const summary = columns[columns.length - 1];
        const status = columns[columns.length - 2];
        const severityRaw = columns[columns.length - 4];
        const category = columns[columns.length - 5];
        const name = columns[columns.length - 6];

        if (!name || !category || !summary)
            continue;
        if (!category.toLowerCase().includes("security"))
            continue;

        findings.push({
            id: `${name}-${findings.length + 1}`,
            summary,
            status,
            severity: normalizeSeverity(severityRaw),
            source: "native-zypper",
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

function parseZypperVersion(output: string): string {
    const firstLine = output.split('\n')
            .map(line => line.trim())
            .find(Boolean) || "";
    if (!firstLine)
        return "unknown";

    return firstLine;
}

export class NativeZypperProvider implements SecurityProvider {
    async getReport(): Promise<SecurityReport> {
        const startedAt = Date.now();
        const output = await cockpit.spawn(ZYPPER_COMMAND, { err: "message", environ: ["LC_ALL=C"] })
                .catch(error => Promise.reject(new Error(formatSpawnError(error))));

        const findings = parseZypperOutput(output.toString());
        const generatedAt = new Date().toISOString();
        const scanSeconds = (Date.now() - startedAt) / 1000;
        const scannerVersionOutput = await cockpit.spawn(ZYPPER_VERSION_COMMAND, { err: "message", environ: ["LC_ALL=C"] }).catch(() => "");
        const metadata = await createReportMetadata({
            generatedAt,
            scanSeconds,
            packageManager: "zypper",
            scannerVersion: parseZypperVersion(scannerVersionOutput.toString()),
            scannerDatasetVersion: "unknown",
        });

        return {
            provider: "native-zypper",
            generatedAt,
            findings,
            summary: createSummary(findings),
            metadata,
        };
    }
}
