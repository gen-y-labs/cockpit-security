/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import cockpit from "cockpit";

import { createReportMetadata } from '../report-metadata';
import type {
    SecurityFinding,
    SecurityProvider,
    SecurityReport,
    SecuritySummary,
} from '../security-report';

const APT_COMMAND = ["apt-get", "-s", "upgrade"];
const APT_VERSION_COMMAND = ["apt-get", "--version"];

function createSummary(findings: SecurityFinding[]): SecuritySummary {
    const summary = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: findings.length,
        total: findings.length,
    };

    return summary;
}

function parseAptOutput(output: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const line of output.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("Inst "))
            continue;
        if (!trimmed.toLowerCase().includes("-security"))
            continue;

        const parts = trimmed.split(/\s+/);
        const packageName = parts[1] || "unknown-package";

        findings.push({
            id: `${packageName}-${findings.length + 1}`,
            summary: trimmed,
            status: "upgradable",
            severity: "unknown",
            source: "native-apt",
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

function parseAptVersion(output: string): string {
    const firstLine = output.split('\n')
            .map(line => line.trim())
            .find(Boolean) || "";
    if (!firstLine)
        return "unknown";

    return firstLine;
}

export class NativeAptProvider implements SecurityProvider {
    async getReport(): Promise<SecurityReport> {
        const startedAt = Date.now();
        const output = await cockpit.spawn(APT_COMMAND, { err: "message", environ: ["LC_ALL=C"] })
                .catch(error => Promise.reject(new Error(formatSpawnError(error))));

        const findings = parseAptOutput(output.toString());
        const generatedAt = new Date().toISOString();
        const scanSeconds = (Date.now() - startedAt) / 1000;
        const scannerVersionOutput = await cockpit.spawn(APT_VERSION_COMMAND, { err: "message", environ: ["LC_ALL=C"] }).catch(() => "");
        const metadata = await createReportMetadata({
            generatedAt,
            scanSeconds,
            packageManager: "apt",
            scannerVersion: parseAptVersion(scannerVersionOutput.toString()),
            scannerDatasetVersion: "unknown",
        });

        return {
            provider: "native-apt",
            generatedAt,
            findings,
            summary: createSummary(findings),
            metadata,
        };
    }
}
