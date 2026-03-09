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

export const OPENSCAP_INSTALL_URL = "https://www.open-scap.org/tools/openscap-base/";
export const SCAP_SECURITY_GUIDE_URL = "https://github.com/ComplianceAsCode/content";

interface OpenScapScanOptions {
    source: string;
}

let cachedReport: SecurityReport | null = null;
let cachedOpenScapVersion: string | null = null;

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

function parseArfResult(arfXml: string): SecurityFinding[] {
    const parsed = new DOMParser().parseFromString(arfXml, "application/xml");
    const parseError = parsed.getElementsByTagName("parsererror")[0];

    if (parseError)
        throw new Error(cockpit.gettext("Failed to parse OpenSCAP ARF output"));

    const ruleTitleById = new Map<string, string>();
    const rules = Array.from(parsed.getElementsByTagNameNS("*", "Rule"));

    for (const rule of rules) {
        const id = rule.getAttribute("id");
        if (!id)
            continue;

        const titleElement = rule.getElementsByTagNameNS("*", "title")[0];
        const title = titleElement?.textContent?.trim();
        if (title)
            ruleTitleById.set(id, title);
    }

    const findings: SecurityFinding[] = [];
    const ruleResults = Array.from(parsed.getElementsByTagNameNS("*", "rule-result"));

    for (const ruleResult of ruleResults) {
        const idref = ruleResult.getAttribute("idref") || cockpit.gettext("unknown-rule");
        const resultElement = ruleResult.getElementsByTagNameNS("*", "result")[0];
        const status = resultElement?.textContent?.trim().toLowerCase() || "unknown";

        const rule = rules.find(item => item.getAttribute("id") === idref);
        const severity = normalizeSeverity(rule?.getAttribute("severity") || undefined);
        const summary = ruleTitleById.get(idref) || idref;

        findings.push({
            id: idref,
            summary,
            severity,
            status,
            source: "openscap",
        });
    }

    return findings;
}

const _ = cockpit.gettext;

function getMissingPackagesHint(): string {
    return cockpit.format(
        _("OpenSCAP compliance prerequisites are missing. Install openscap-utils and scap-security-guide. OpenSCAP: $0 SCAP Security Guide: $1"),
        OPENSCAP_INSTALL_URL,
        SCAP_SECURITY_GUIDE_URL
    );
}

function formatSpawnError(error: unknown): string {
    const installHint = getMissingPackagesHint();

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

function getOpenScapCommand(source: string): string[] {
    const script = [
        "set -eu",
        "result_file=\"$(mktemp /tmp/cockpit-security-openscap-XXXXXX.xml)\"",
        "cleanup() { rm -f \"$result_file\"; }",
        "trap cleanup EXIT",
        "rc=0",
        "oscap xccdf eval --results-arf \"$result_file\" \"$1\" >/dev/null 2>&1 || rc=$?",
        "if [ \"$rc\" -ne 0 ] && [ \"$rc\" -ne 2 ]; then",
        "  echo \"OpenSCAP exited with status $rc\" >&2",
        "  exit \"$rc\"",
        "fi",
        "cat \"$result_file\"",
    ].join("\n");

    return ["/bin/sh", "-ec", script, "sh", source];
}

function getOpenScapVersionCommand(): string[] {
    return ["oscap", "--version"];
}

function parseOpenScapVersion(output: string): string {
    const versionMatch = output.match(/(?:^|\s)(\d+\.\d+\.\d+)\b/);
    if (versionMatch && versionMatch[1])
        return versionMatch[1];

    const firstLine = output.split('\n')
            .map(line => line.trim())
            .find(Boolean) || "";
    if (!firstLine)
        return "unknown";

    return firstLine;
}

async function getOpenScapVersion(): Promise<string> {
    if (cachedOpenScapVersion)
        return cachedOpenScapVersion;

    const output = await cockpit.spawn(getOpenScapVersionCommand(), { err: "message", environ: ["LC_ALL=C"] }).catch(() => "");
    cachedOpenScapVersion = parseOpenScapVersion(output.toString());
    return cachedOpenScapVersion;
}

export async function listOpenScapSources(): Promise<string[]> {
    const script = [
        "command -v oscap >/dev/null 2>&1 || exit 127",
        "if [ -d /usr/share/xml/scap ]; then",
        "  find /usr/share/xml/scap -type f -name '*-ds.xml' 2>/dev/null | sort -u",
        "fi",
    ].join("\n");

    const output = await cockpit.spawn(["/bin/sh", "-ec", script], { err: "message", environ: ["LC_ALL=C"] })
            .catch(error => Promise.reject(new Error(formatSpawnError(error))));

    const sources = output
            .toString()
            .split("\n")
            .map(line => line.trim())
            .filter(Boolean);

    if (sources.length === 0)
        throw new Error(getMissingPackagesHint());

    return sources;
}

export class OpenScapProvider implements SecurityProvider {
    private source: string;

    constructor(options: OpenScapScanOptions) {
        this.source = options.source;
    }

    async getReport(): Promise<SecurityReport> {
        const startedAt = Date.now();
        const output = await cockpit.spawn(getOpenScapCommand(this.source), { err: "message", environ: ["LC_ALL=C"] })
                .catch(error => Promise.reject(new Error(formatSpawnError(error))));

        const findings = parseArfResult(output.toString());
        const generatedAt = new Date().toISOString();
        const scanSeconds = (Date.now() - startedAt) / 1000;
        const metadata = await createReportMetadata({
            generatedAt,
            scanSeconds,
            scannerVersion: await getOpenScapVersion(),
            scannerDatasetVersion: "unknown",
        });
        const report: SecurityReport = {
            provider: "openscap",
            generatedAt,
            findings,
            summary: createSummary(findings),
            metadata,
        };

        cachedReport = report;
        return report;
    }
}

export function getCachedOpenScapReport(): SecurityReport | null {
    return cachedReport;
}
