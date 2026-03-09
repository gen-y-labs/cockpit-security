#!/usr/bin/env node

import { execFile } from "node:child_process";
import { accessSync, constants as fsConstants } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const DATASET_SCHEMA_VERSION = "1.0";

const PACKAGE_MANAGERS = new Set(["apt", "dnf", "zypper", "unknown"]);
const ENVIRONMENT_TYPES = new Set(["vm", "cloud-vm", "bare-metal", "unknown"]);
const HOST_ROLES = new Set(["minimal", "web-server", "db-server", "container-host", "generic", "unknown"]);

const PATCH_REPORT_CANDIDATES = [
    "patch-report.json",
    "vulnerabilities-native-zypper.json",
    "vulnerabilities-native-apt.json",
];

const TRIVY_REPORT_CANDIDATES = [
    "trivy-report.json",
    "vulnerabilities-trivy.json",
];

const OPENSCAP_REPORT_CANDIDATES = [
    "openscap-report.json",
    "vulnerabilities-openscap.json",
];

const OPENSCAP_REPORT_PATTERNS = [
    /^vulnerabilities-openscap.*\.json$/,
    /^openscap-report(?:-.+)?\.json$/,
];

function createDefaultRecord() {
    return {
        dataset_schema_version: DATASET_SCHEMA_VERSION,
        scan_id: "unknown",
        scan_timestamp: "unknown",

        host_id: "unknown",
        distro: "unknown",
        distro_version: "unknown",
        kernel_version: "unknown",
        environment_type: "unknown",
        host_role: "unknown",
        package_manager: "unknown",

        cpu_count: 0,
        memory_gb: 0,
        installed_package_count: 0,
        running_service_count: 0,

        patch_security_updates: 0,
        patch_critical_updates: 0,
        patch_high_updates: 0,
        patch_medium_updates: 0,
        patch_low_updates: 0,

        cve_critical: 0,
        cve_high: 0,
        cve_medium: 0,
        cve_low: 0,
        cve_total: 0,

        compliance_high_fail: 0,
        compliance_medium_fail: 0,
        compliance_low_fail: 0,
        compliance_total_fail: 0,
        compliance_profile: "unknown",

        patch_scan_seconds: 0,
        vuln_scan_seconds: 0,
        compliance_scan_seconds: 0,

        scanner_trivy_version: "unknown",
        scanner_openscap_version: "unknown",
        scanner_dataset_version: "unknown",
    };
}

function toNumber(value) {
    if (typeof value === "number" && Number.isFinite(value))
        return value;

    if (typeof value === "string" && value.trim() !== "") {
        const parsed = Number(value);
        if (Number.isFinite(parsed))
            return parsed;
    }

    return null;
}

function toStringValue(value) {
    if (typeof value === "string" && value.trim() !== "")
        return value.trim();

    return null;
}

function setStringField(record, defaultsUsed, field, value) {
    const normalized = toStringValue(value);
    if (normalized === null) {
        defaultsUsed.add(field);
        return;
    }

    record[field] = normalized;
    if (normalized.toLowerCase() === "unknown")
        defaultsUsed.add(field);
}

function setChoiceField(record, defaultsUsed, field, value, allowed) {
    const normalized = toStringValue(value)?.toLowerCase() || null;
    if (normalized && allowed.has(normalized)) {
        record[field] = normalized;
        if (normalized === "unknown")
            defaultsUsed.add(field);
        return;
    }

    defaultsUsed.add(field);
}

function setNumberField(record, defaultsUsed, field, value) {
    const normalized = toNumber(value);
    if (normalized === null) {
        defaultsUsed.add(field);
        return;
    }

    record[field] = normalized;
}

function findPathValue(obj, dottedPath) {
    if (!obj || typeof obj !== "object")
        return undefined;

    let current = obj;
    for (const segment of dottedPath.split(".")) {
        if (!current || typeof current !== "object")
            return undefined;

        current = current[segment];
    }

    return current;
}

function firstNumber(...candidates) {
    for (const candidate of candidates) {
        const number = toNumber(candidate);
        if (number !== null)
            return number;
    }

    return null;
}

function firstString(...candidates) {
    for (const candidate of candidates) {
        const stringValue = toStringValue(candidate);
        if (stringValue !== null)
            return stringValue;
    }

    return null;
}

function getReportMetadata(report) {
    if (!report || typeof report !== "object")
        return {};
    if (!report.metadata || typeof report.metadata !== "object")
        return {};
    return report.metadata;
}

function normalizeProfileLabel(value) {
    const normalized = toStringValue(value)?.toLowerCase() || "";
    return normalized
            .replace(/\.json$/i, "")
            .replace(/[^a-z0-9._-]+/g, "-")
            .replace(/^-+/, "")
            .replace(/-+$/, "");
}

export function deriveComplianceProfileFromPath(filePath) {
    const fileName = path.basename(filePath || "");
    const withoutExtension = fileName.replace(/\.json$/i, "");

    const vulnerabilitiesMatch = withoutExtension.match(/^vulnerabilities-openscap-(.+)$/i);
    if (vulnerabilitiesMatch && vulnerabilitiesMatch[1])
        return normalizeProfileLabel(vulnerabilitiesMatch[1]) || "unknown";

    const openscapMatch = withoutExtension.match(/^openscap-report-(.+)$/i);
    if (openscapMatch && openscapMatch[1])
        return normalizeProfileLabel(openscapMatch[1]) || "unknown";

    return "unknown";
}

function inferComplianceProfile(options = {}) {
    const explicitProfile = normalizeProfileLabel(options.selectedOpenScapProfile);
    if (explicitProfile)
        return explicitProfile;

    const report = options.openscapReport && typeof options.openscapReport === "object"
        ? options.openscapReport
        : {};
    const reportMetadata = getReportMetadata(report);

    const metadataProfile = firstString(
        options.metadata?.compliance_profile,
        report.compliance_profile,
        report.profile,
        reportMetadata.compliance_profile,
        reportMetadata.profile,
        reportMetadata.source,
        reportMetadata.source_id
    );
    const normalizedMetadataProfile = normalizeProfileLabel(metadataProfile);
    if (normalizedMetadataProfile)
        return normalizedMetadataProfile;

    const fromPath = deriveComplianceProfileFromPath(options.openscapReportPath);
    return fromPath || "unknown";
}

function safeCountFromLines(output) {
    if (!output)
        return 0;

    return output
            .split("\n")
            .map(line => line.trim())
            .filter(Boolean)
            .length;
}

async function readFileText(filePath) {
    try {
        return await fs.readFile(filePath, "utf8");
    } catch {
        return "";
    }
}

async function readOptionalJson(filePath, warnings, label) {
    if (!filePath)
        return null;

    try {
        const content = await fs.readFile(filePath, "utf8");
        return JSON.parse(content);
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        warnings.push(`Failed to read ${label} report from ${filePath}: ${message}`);
        return null;
    }
}

async function runCommand(command, args) {
    try {
        const { stdout } = await execFileAsync(command, args, {
            encoding: "utf8",
            maxBuffer: 20 * 1024 * 1024,
        });
        return stdout.trim();
    } catch {
        return "";
    }
}

function commandExists(command) {
    const pathValue = process.env.PATH || "";
    for (const segment of pathValue.split(path.delimiter)) {
        if (!segment)
            continue;

        const candidate = path.join(segment, command);
        try {
            accessSync(candidate, fsConstants.X_OK);
            return true;
        } catch {
            // keep checking
        }
    }

    return false;
}

function parseOsRelease(content) {
    const fields = {};
    if (!content)
        return fields;

    for (const line of content.split("\n")) {
        if (!line || line.startsWith("#"))
            continue;

        const separator = line.indexOf("=");
        if (separator < 0)
            continue;

        const key = line.slice(0, separator).trim();
        const rawValue = line.slice(separator + 1).trim();
        const value = rawValue.startsWith("\"") && rawValue.endsWith("\"")
            ? rawValue.slice(1, -1)
            : rawValue;
        fields[key] = value;
    }

    return fields;
}

function detectPackageManager(distro, distroLike) {
    const fingerprint = `${distro || ""} ${distroLike || ""}`.toLowerCase();

    if (fingerprint.includes("ubuntu") || fingerprint.includes("debian"))
        return "apt";
    if (fingerprint.includes("opensuse") || fingerprint.includes("sles") || fingerprint.includes("suse"))
        return "zypper";
    if (fingerprint.includes("fedora") ||
        fingerprint.includes("rhel") ||
        fingerprint.includes("centos") ||
        fingerprint.includes("rocky") ||
        fingerprint.includes("almalinux") ||
        fingerprint.includes("amzn")) {
        return "dnf";
    }

    if (commandExists("apt-get"))
        return "apt";
    if (commandExists("dnf"))
        return "dnf";
    if (commandExists("zypper"))
        return "zypper";

    return "unknown";
}

async function countInstalledPackages(packageManager) {
    if ((packageManager === "apt" || packageManager === "unknown") && commandExists("dpkg-query")) {
        const output = await runCommand("dpkg-query", ["-W", "-f=${Package}\n"]);
        const count = safeCountFromLines(output);
        if (count > 0)
            return count;
    }

    if ((packageManager === "dnf" || packageManager === "zypper" || packageManager === "unknown") && commandExists("rpm")) {
        const output = await runCommand("rpm", ["-qa"]);
        const count = safeCountFromLines(output);
        if (count > 0)
            return count;
    }

    return 0;
}

async function countRunningServices() {
    if (!commandExists("systemctl"))
        return 0;

    const output = await runCommand("systemctl", [
        "list-units",
        "--type=service",
        "--state=running",
        "--no-legend",
        "--no-pager",
        "--plain",
    ]);

    return safeCountFromLines(output);
}

async function collectHostMetadata(overrides) {
    const osReleaseContent = await readFileText("/etc/os-release");
    const osRelease = parseOsRelease(osReleaseContent);

    const hostId = firstString(
        overrides?.host_id,
        (await readFileText("/etc/hostname")).trim(),
        os.hostname()
    );

    const distro = firstString(overrides?.distro, osRelease.ID)?.toLowerCase() || null;
    const distroVersion = firstString(overrides?.distro_version, osRelease.VERSION_ID);
    const kernelVersion = firstString(
        overrides?.kernel_version,
        await runCommand("uname", ["-r"]),
        os.release()
    );

    const packageManager = firstString(
        overrides?.package_manager,
        detectPackageManager(distro, osRelease.ID_LIKE)
    )?.toLowerCase() || "unknown";

    const cpuCount = firstNumber(overrides?.cpu_count, os.cpus()?.length || 0);
    const memoryGb = firstNumber(
        overrides?.memory_gb,
        Number((os.totalmem() / (1024 ** 3)).toFixed(1))
    );
    const installedPackageCount = firstNumber(
        overrides?.installed_package_count,
        await countInstalledPackages(packageManager)
    );
    const runningServiceCount = firstNumber(
        overrides?.running_service_count,
        await countRunningServices()
    );

    return {
        host_id: hostId,
        distro,
        distro_version: distroVersion,
        kernel_version: kernelVersion,
        package_manager: packageManager,
        environment_type: overrides?.environment_type,
        host_role: overrides?.host_role,
        cpu_count: cpuCount,
        memory_gb: memoryGb,
        installed_package_count: installedPackageCount,
        running_service_count: runningServiceCount,
    };
}

function mapPatchSignals(report, defaultsUsed) {
    const fields = [
        "patch_security_updates",
        "patch_critical_updates",
        "patch_high_updates",
        "patch_medium_updates",
        "patch_low_updates",
    ];

    const summary = report && typeof report === "object" && report.summary && typeof report.summary === "object"
        ? report.summary
        : null;
    if (!summary) {
        for (const field of fields)
            defaultsUsed.add(field);

        return {
            patch_security_updates: 0,
            patch_critical_updates: 0,
            patch_high_updates: 0,
            patch_medium_updates: 0,
            patch_low_updates: 0,
        };
    }

    return {
        patch_security_updates: toNumber(summary.total) ?? 0,
        patch_critical_updates: toNumber(summary.critical) ?? 0,
        patch_high_updates: toNumber(summary.high) ?? 0,
        patch_medium_updates: toNumber(summary.medium) ?? 0,
        patch_low_updates: toNumber(summary.low) ?? 0,
    };
}

function mapVulnerabilitySignals(report, defaultsUsed) {
    const fields = [
        "cve_critical",
        "cve_high",
        "cve_medium",
        "cve_low",
        "cve_total",
    ];

    const summary = report && typeof report === "object" && report.summary && typeof report.summary === "object"
        ? report.summary
        : null;
    if (!summary) {
        for (const field of fields)
            defaultsUsed.add(field);

        return {
            cve_critical: 0,
            cve_high: 0,
            cve_medium: 0,
            cve_low: 0,
            cve_total: 0,
        };
    }

    const critical = toNumber(summary.critical) ?? 0;
    const high = toNumber(summary.high) ?? 0;
    const medium = toNumber(summary.medium) ?? 0;
    const low = toNumber(summary.low) ?? 0;
    const total = toNumber(summary.total) ?? (critical + high + medium + low);

    return {
        cve_critical: critical,
        cve_high: high,
        cve_medium: medium,
        cve_low: low,
        cve_total: total,
    };
}

function mapComplianceSignals(report, defaultsUsed) {
    const fields = [
        "compliance_high_fail",
        "compliance_medium_fail",
        "compliance_low_fail",
        "compliance_total_fail",
    ];

    if (!report || typeof report !== "object") {
        for (const field of fields)
            defaultsUsed.add(field);

        return {
            compliance_high_fail: 0,
            compliance_medium_fail: 0,
            compliance_low_fail: 0,
            compliance_total_fail: 0,
        };
    }

    const summary = report.summary && typeof report.summary === "object"
        ? report.summary
        : null;
    if (!summary) {
        for (const field of fields)
            defaultsUsed.add(field);

        return {
            compliance_high_fail: 0,
            compliance_medium_fail: 0,
            compliance_low_fail: 0,
            compliance_total_fail: 0,
        };
    }

    const high = toNumber(summary.high) ?? 0;
    const medium = toNumber(summary.medium) ?? 0;
    const low = toNumber(summary.low) ?? 0;
    const total = toNumber(summary.total) ?? (high + medium + low);

    return {
        compliance_high_fail: high,
        compliance_medium_fail: medium,
        compliance_low_fail: low,
        compliance_total_fail: total,
    };
}

function makeIsoTimestamp(input) {
    const date = input ? new Date(input) : new Date();
    if (Number.isNaN(date.getTime()))
        return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

    return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function formatScanIdTimestamp(isoTimestamp) {
    const date = new Date(isoTimestamp);
    if (Number.isNaN(date.getTime()))
        return "unknown";

    const pad = value => value.toString().padStart(2, "0");
    const year = date.getUTCFullYear();
    const month = pad(date.getUTCMonth() + 1);
    const day = pad(date.getUTCDate());
    const hour = pad(date.getUTCHours());
    const minute = pad(date.getUTCMinutes());
    const second = pad(date.getUTCSeconds());

    return `${year}-${month}-${day}T${hour}-${minute}-${second}Z`;
}

function sanitizeForId(value) {
    const normalized = toStringValue(value)?.toLowerCase() || "unknown-host";
    const sanitized = normalized
            .replace(/[^a-z0-9._-]+/g, "-")
            .replace(/^-+/, "")
            .replace(/-+$/, "");

    return sanitized || "unknown-host";
}

function extractRuntimeAndScannerMetadata(options) {
    const metadata = options.metadata || {};
    const patchReport = options.patchReport || {};
    const trivyReport = options.trivyReport || {};
    const openscapReport = options.openscapReport || {};

    const patchScanSeconds = firstNumber(
        options.patch_scan_seconds,
        metadata.patch_scan_seconds,
        findPathValue(metadata, "runtime.patch_scan_seconds"),
        patchReport.patch_scan_seconds,
        patchReport.scan_seconds,
        patchReport.scanDurationSeconds,
        findPathValue(patchReport, "metadata.scan_seconds"),
        findPathValue(patchReport, "metadata.scanDurationSeconds")
    );

    const vulnScanSeconds = firstNumber(
        options.vuln_scan_seconds,
        metadata.vuln_scan_seconds,
        findPathValue(metadata, "runtime.vuln_scan_seconds"),
        trivyReport.vuln_scan_seconds,
        trivyReport.scan_seconds,
        trivyReport.scanDurationSeconds,
        findPathValue(trivyReport, "metadata.scan_seconds"),
        findPathValue(trivyReport, "metadata.scanDurationSeconds")
    );

    const complianceScanSeconds = firstNumber(
        options.compliance_scan_seconds,
        metadata.compliance_scan_seconds,
        findPathValue(metadata, "runtime.compliance_scan_seconds"),
        openscapReport.compliance_scan_seconds,
        openscapReport.scan_seconds,
        openscapReport.scanDurationSeconds,
        findPathValue(openscapReport, "metadata.scan_seconds"),
        findPathValue(openscapReport, "metadata.scanDurationSeconds")
    );

    const scannerTrivyVersion = firstString(
        options.scanner_trivy_version,
        metadata.scanner_trivy_version,
        findPathValue(metadata, "scanner.trivy_version"),
        trivyReport.scanner_trivy_version,
        trivyReport.scannerVersion,
        trivyReport.trivyVersion,
        findPathValue(trivyReport, "metadata.scanner_version"),
        findPathValue(trivyReport, "metadata.scanner_trivy_version"),
        findPathValue(trivyReport, "metadata.trivy_version"),
        findPathValue(trivyReport, "metadata.trivyVersion")
    );

    const scannerOpenScapVersion = firstString(
        options.scanner_openscap_version,
        metadata.scanner_openscap_version,
        findPathValue(metadata, "scanner.openscap_version"),
        openscapReport.scanner_openscap_version,
        openscapReport.scannerVersion,
        openscapReport.openscapVersion,
        findPathValue(openscapReport, "metadata.scanner_version"),
        findPathValue(openscapReport, "metadata.scanner_openscap_version"),
        findPathValue(openscapReport, "metadata.openscap_version"),
        findPathValue(openscapReport, "metadata.openscapVersion")
    );

    const scannerDatasetVersion = firstString(
        options.scanner_dataset_version,
        metadata.scanner_dataset_version,
        findPathValue(metadata, "scanner.dataset_version"),
        trivyReport.scanner_dataset_version,
        openscapReport.scanner_dataset_version,
        findPathValue(trivyReport, "metadata.scanner_dataset_version"),
        findPathValue(openscapReport, "metadata.scanner_dataset_version"),
        findPathValue(trivyReport, "metadata.scannerDatasetVersion"),
        findPathValue(openscapReport, "metadata.scannerDatasetVersion"),
        findPathValue(trivyReport, "metadata.db_version"),
        findPathValue(openscapReport, "metadata.content_version")
    );

    return {
        patch_scan_seconds: patchScanSeconds,
        vuln_scan_seconds: vulnScanSeconds,
        compliance_scan_seconds: complianceScanSeconds,
        scanner_trivy_version: scannerTrivyVersion,
        scanner_openscap_version: scannerOpenScapVersion,
        scanner_dataset_version: scannerDatasetVersion,
    };
}

function mergeReportDerivedFields(record, mapped) {
    for (const [field, value] of Object.entries(mapped))
        record[field] = value;
}

async function resolveExistingPath(hostDir, candidates) {
    for (const candidate of candidates) {
        const resolvedPath = path.join(hostDir, candidate);
        try {
            await fs.access(resolvedPath);
            return resolvedPath;
        } catch {
            // keep checking candidates
        }
    }

    return null;
}

function isOpenScapCandidateFile(fileName) {
    if (OPENSCAP_REPORT_CANDIDATES.includes(fileName))
        return true;

    return OPENSCAP_REPORT_PATTERNS.some(pattern => pattern.test(fileName));
}

export async function listOpenScapCandidatePaths(hostDir) {
    let entries = [];
    try {
        entries = await fs.readdir(hostDir, { withFileTypes: true });
    } catch {
        entries = [];
    }

    return entries
            .filter(entry => entry.isFile() && isOpenScapCandidateFile(entry.name))
            .map(entry => path.join(hostDir, entry.name))
            .sort((left, right) => left.localeCompare(right));
}

export async function resolveHostDirReportPaths(hostDir) {
    let entries = [];
    try {
        entries = await fs.readdir(hostDir, { withFileTypes: true });
    } catch {
        entries = [];
    }

    const files = entries
            .filter(entry => entry.isFile())
            .map(entry => entry.name);

    const findByPattern = pattern => {
        const match = files.find(fileName => pattern.test(fileName));
        return match ? path.join(hostDir, match) : null;
    };

    return {
        patchReportPath: (await resolveExistingPath(hostDir, PATCH_REPORT_CANDIDATES)) ||
            findByPattern(/^vulnerabilities-native-(zypper|apt)\.json$/),
        trivyReportPath: (await resolveExistingPath(hostDir, TRIVY_REPORT_CANDIDATES)) ||
            findByPattern(/^vulnerabilities-trivy(?:-.+)?\.json$/),
        openscapReportPath: (await listOpenScapCandidatePaths(hostDir))[0] ||
            (await resolveExistingPath(hostDir, OPENSCAP_REPORT_CANDIDATES)) ||
            findByPattern(/^vulnerabilities-openscap.*\.json$/),
    };
}

export async function collectHostSecurityRecord(options = {}) {
    const defaultsUsed = new Set();
    const warnings = [];

    const patchReport = await readOptionalJson(options.patchReportPath, warnings, "patch");
    const trivyReport = await readOptionalJson(options.trivyReportPath, warnings, "Trivy");
    const openscapReport = await readOptionalJson(options.openscapReportPath, warnings, "OpenSCAP");
    const metadata = await readOptionalJson(options.metadataPath, warnings, "metadata");
    const patchMetadata = getReportMetadata(patchReport);
    const trivyMetadata = getReportMetadata(trivyReport);
    const openscapMetadata = getReportMetadata(openscapReport);
    const complianceProfile = inferComplianceProfile({
        selectedOpenScapProfile: options.selectedOpenScapProfile,
        metadata,
        openscapReport,
        openscapReportPath: options.openscapReportPath,
    });

    const hostMetadata = await collectHostMetadata({
        host_id: firstString(metadata?.host_id, patchMetadata.host_id, trivyMetadata.host_id, openscapMetadata.host_id),
        distro: firstString(metadata?.distro, patchMetadata.distro, trivyMetadata.distro, openscapMetadata.distro),
        distro_version: firstString(metadata?.distro_version, patchMetadata.distro_version, trivyMetadata.distro_version, openscapMetadata.distro_version),
        kernel_version: firstString(metadata?.kernel_version, patchMetadata.kernel_version, trivyMetadata.kernel_version, openscapMetadata.kernel_version),
        environment_type: firstString(metadata?.environment_type, patchMetadata.environment_type, trivyMetadata.environment_type, openscapMetadata.environment_type),
        host_role: firstString(metadata?.host_role, patchMetadata.host_role, trivyMetadata.host_role, openscapMetadata.host_role),
        package_manager: firstString(metadata?.package_manager, patchMetadata.package_manager, trivyMetadata.package_manager, openscapMetadata.package_manager),
        cpu_count: firstNumber(metadata?.cpu_count, patchMetadata.cpu_count, trivyMetadata.cpu_count, openscapMetadata.cpu_count),
        memory_gb: firstNumber(metadata?.memory_gb, patchMetadata.memory_gb, trivyMetadata.memory_gb, openscapMetadata.memory_gb),
        installed_package_count: firstNumber(
            metadata?.installed_package_count,
            patchMetadata.installed_package_count,
            trivyMetadata.installed_package_count,
            openscapMetadata.installed_package_count
        ),
        running_service_count: firstNumber(
            metadata?.running_service_count,
            patchMetadata.running_service_count,
            trivyMetadata.running_service_count,
            openscapMetadata.running_service_count
        ),
    });
    const runtimeAndScannerMetadata = extractRuntimeAndScannerMetadata({
        ...metadata,
        patchReport,
        trivyReport,
        openscapReport,
        metadata,
    });

    const record = createDefaultRecord();
    const scanTimestamp = makeIsoTimestamp(
        firstString(
            options.scanTimestamp,
            metadata?.scan_timestamp,
            patchMetadata.scan_timestamp,
            patchReport?.generatedAt,
            trivyMetadata.scan_timestamp,
            trivyReport?.generatedAt,
            openscapMetadata.scan_timestamp,
            openscapReport?.generatedAt
        )
    );

    record.scan_timestamp = scanTimestamp;
    setStringField(record, defaultsUsed, "host_id", hostMetadata.host_id);
    setStringField(record, defaultsUsed, "distro", hostMetadata.distro);
    setStringField(record, defaultsUsed, "distro_version", hostMetadata.distro_version);
    setStringField(record, defaultsUsed, "kernel_version", hostMetadata.kernel_version);
    setChoiceField(record, defaultsUsed, "environment_type", hostMetadata.environment_type, ENVIRONMENT_TYPES);
    setChoiceField(record, defaultsUsed, "host_role", hostMetadata.host_role, HOST_ROLES);
    setChoiceField(record, defaultsUsed, "package_manager", hostMetadata.package_manager, PACKAGE_MANAGERS);

    setNumberField(record, defaultsUsed, "cpu_count", hostMetadata.cpu_count);
    setNumberField(record, defaultsUsed, "memory_gb", hostMetadata.memory_gb);
    setNumberField(record, defaultsUsed, "installed_package_count", hostMetadata.installed_package_count);
    setNumberField(record, defaultsUsed, "running_service_count", hostMetadata.running_service_count);

    mergeReportDerivedFields(record, mapPatchSignals(patchReport, defaultsUsed));
    mergeReportDerivedFields(record, mapVulnerabilitySignals(trivyReport, defaultsUsed));
    mergeReportDerivedFields(record, mapComplianceSignals(openscapReport, defaultsUsed));
    setStringField(record, defaultsUsed, "compliance_profile", complianceProfile);

    setNumberField(record, defaultsUsed, "patch_scan_seconds", runtimeAndScannerMetadata.patch_scan_seconds);
    setNumberField(record, defaultsUsed, "vuln_scan_seconds", runtimeAndScannerMetadata.vuln_scan_seconds);
    setNumberField(record, defaultsUsed, "compliance_scan_seconds", runtimeAndScannerMetadata.compliance_scan_seconds);

    setStringField(record, defaultsUsed, "scanner_trivy_version", runtimeAndScannerMetadata.scanner_trivy_version);
    setStringField(record, defaultsUsed, "scanner_openscap_version", runtimeAndScannerMetadata.scanner_openscap_version);
    setStringField(record, defaultsUsed, "scanner_dataset_version", runtimeAndScannerMetadata.scanner_dataset_version);

    const scanIdTimestamp = formatScanIdTimestamp(scanTimestamp);
    record.scan_id = `${scanIdTimestamp}-${sanitizeForId(record.host_id)}`;

    return {
        record,
        defaultedFields: [...defaultsUsed].sort(),
        warnings,
    };
}

export async function writeNormalizedRecord(outputPath, record) {
    await fs.writeFile(outputPath, `${JSON.stringify(record, null, 2)}\n`, "utf8");
}
