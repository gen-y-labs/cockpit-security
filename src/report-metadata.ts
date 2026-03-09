/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import cockpit from "cockpit";

import type {
    EnvironmentType,
    HostRole,
    PackageManager,
    SecurityReportMetadata,
} from './security-report';

const UNKNOWN = "unknown";
const DPKG_COUNT_COMMAND = "dpkg-query -W -f='$" + "{Package}\\n' 2>/dev/null | wc -l";

interface BaseReportMetadata {
    host_id: string;
    distro: string;
    distro_version: string;
    kernel_version: string;
    environment_type: EnvironmentType;
    host_role: HostRole;
    package_manager: PackageManager;
    cpu_count: number;
    memory_gb: number;
    installed_package_count: number;
    running_service_count: number;
}

interface CreateMetadataOptions {
    generatedAt: string;
    scanSeconds: number;
    scannerVersion?: string;
    scannerDatasetVersion?: string;
    packageManager?: PackageManager;
}

let cachedBaseMetadataPromise: Promise<BaseReportMetadata> | null = null;

function toNonEmptyString(value: unknown): string | null {
    return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

function toFiniteNumber(value: unknown): number | null {
    if (typeof value === "number" && Number.isFinite(value))
        return value;

    if (typeof value === "string" && value.trim() !== "") {
        const parsed = Number(value);
        if (Number.isFinite(parsed))
            return parsed;
    }

    return null;
}

function normalizeInteger(value: unknown): number {
    const parsed = toFiniteNumber(value);
    if (parsed === null || parsed < 0)
        return 0;
    return Math.round(parsed);
}

function normalizeMemoryGb(value: unknown): number {
    const parsed = toFiniteNumber(value);
    if (parsed === null || parsed < 0)
        return 0;
    return Math.round(parsed * 10) / 10;
}

function normalizeScanSeconds(value: unknown): number {
    const parsed = toFiniteNumber(value);
    if (parsed === null || parsed < 0)
        return 0;
    return Math.round(parsed * 100) / 100;
}

function normalizePackageManager(value: unknown): PackageManager {
    const normalized = toNonEmptyString(value)?.toLowerCase();
    if (normalized === "apt" || normalized === "dnf" || normalized === "zypper")
        return normalized;
    return "unknown";
}

function sanitizeString(value: unknown): string {
    return toNonEmptyString(value) || UNKNOWN;
}

function parseOsRelease(content: string): Record<string, string> {
    const fields: Record<string, string> = {};

    for (const line of content.split('\n')) {
        if (!line || line.startsWith('#'))
            continue;

        const separator = line.indexOf('=');
        if (separator < 0)
            continue;

        const key = line.slice(0, separator).trim();
        let value = line.slice(separator + 1).trim();
        if (value.startsWith('"') && value.endsWith('"'))
            value = value.slice(1, -1);

        fields[key] = value;
    }

    return fields;
}

async function readFileTrimmed(path: string): Promise<string> {
    try {
        const content = await cockpit.file(path).read();
        return content?.toString().trim() || "";
    } catch {
        return "";
    }
}

async function runCommand(command: string[]): Promise<string> {
    try {
        const output = await cockpit.spawn(command, { err: "message", environ: ["LC_ALL=C"] });
        return output.toString().trim();
    } catch {
        return "";
    }
}

function detectPackageManagerFromDistro(osId: string, osIdLike: string): PackageManager {
    const fingerprint = `${osId} ${osIdLike}`.toLowerCase();
    if (fingerprint.includes("ubuntu") || fingerprint.includes("debian"))
        return "apt";
    if (fingerprint.includes("opensuse") || fingerprint.includes("suse") || fingerprint.includes("sles"))
        return "zypper";
    if (fingerprint.includes("fedora") ||
        fingerprint.includes("rhel") ||
        fingerprint.includes("centos") ||
        fingerprint.includes("rocky") ||
        fingerprint.includes("almalinux") ||
        fingerprint.includes("amzn")) {
        return "dnf";
    }

    return "unknown";
}

async function commandExists(command: string): Promise<boolean> {
    const output = await runCommand(["/bin/sh", "-ec", `command -v ${command} >/dev/null 2>&1 && echo yes || true`]);
    return output === "yes";
}

async function detectPackageManager(osId: string, osIdLike: string): Promise<PackageManager> {
    const fromDistro = detectPackageManagerFromDistro(osId, osIdLike);
    if (fromDistro !== "unknown")
        return fromDistro;

    if (await commandExists("apt-get"))
        return "apt";
    if (await commandExists("dnf"))
        return "dnf";
    if (await commandExists("zypper"))
        return "zypper";

    return "unknown";
}

async function getCpuCount(): Promise<number> {
    const nproc = await runCommand(["/bin/sh", "-ec", "nproc 2>/dev/null || true"]);
    const parsedNproc = toFiniteNumber(nproc);
    if (parsedNproc !== null && parsedNproc > 0)
        return normalizeInteger(parsedNproc);

    const getconf = await runCommand(["getconf", "_NPROCESSORS_ONLN"]);
    const parsedGetconf = toFiniteNumber(getconf);
    if (parsedGetconf !== null && parsedGetconf > 0)
        return normalizeInteger(parsedGetconf);

    return 0;
}

async function getMemoryGb(): Promise<number> {
    const output = await runCommand(["/bin/sh", "-ec", "awk '/MemTotal:/ { printf \"%.1f\", $2/1048576; exit }' /proc/meminfo 2>/dev/null || true"]);
    return normalizeMemoryGb(output);
}

async function getInstalledPackageCount(packageManager: PackageManager): Promise<number> {
    if (packageManager === "apt") {
        const output = await runCommand(["/bin/sh", "-ec", DPKG_COUNT_COMMAND]);
        return normalizeInteger(output);
    }

    if (packageManager === "dnf" || packageManager === "zypper") {
        const output = await runCommand(["/bin/sh", "-ec", "rpm -qa 2>/dev/null | wc -l"]);
        return normalizeInteger(output);
    }

    const aptCount = await runCommand(["/bin/sh", "-ec", DPKG_COUNT_COMMAND]);
    const normalizedAptCount = normalizeInteger(aptCount);
    if (normalizedAptCount > 0)
        return normalizedAptCount;

    const rpmCount = await runCommand(["/bin/sh", "-ec", "rpm -qa 2>/dev/null | wc -l"]);
    return normalizeInteger(rpmCount);
}

async function getRunningServiceCount(): Promise<number> {
    const output = await runCommand([
        "/bin/sh",
        "-ec",
        "if command -v systemctl >/dev/null 2>&1; then systemctl list-units --type=service --state=running --no-legend --no-pager --plain 2>/dev/null | wc -l; else echo 0; fi"
    ]);

    return normalizeInteger(output);
}

async function collectBaseReportMetadata(): Promise<BaseReportMetadata> {
    const [hostname, osReleaseRaw, kernelVersion] = await Promise.all([
        readFileTrimmed('/etc/hostname'),
        readFileTrimmed('/etc/os-release'),
        runCommand(["uname", "-r"]),
    ]);

    const osRelease = parseOsRelease(osReleaseRaw);
    const distro = sanitizeString(osRelease.ID).toLowerCase();
    const distroVersion = sanitizeString(osRelease.VERSION_ID);
    const packageManager = await detectPackageManager(distro, osRelease.ID_LIKE || "");

    const [cpuCount, memoryGb, installedPackageCount, runningServiceCount] = await Promise.all([
        getCpuCount(),
        getMemoryGb(),
        getInstalledPackageCount(packageManager),
        getRunningServiceCount(),
    ]);

    return {
        host_id: sanitizeString(hostname),
        distro,
        distro_version: distroVersion,
        kernel_version: sanitizeString(kernelVersion),
        environment_type: "unknown",
        host_role: "unknown",
        package_manager: packageManager,
        cpu_count: cpuCount,
        memory_gb: memoryGb,
        installed_package_count: installedPackageCount,
        running_service_count: runningServiceCount,
    };
}

async function getBaseReportMetadata(): Promise<BaseReportMetadata> {
    if (!cachedBaseMetadataPromise) {
        cachedBaseMetadataPromise = collectBaseReportMetadata()
                .catch(() => ({
                    host_id: UNKNOWN,
                    distro: UNKNOWN,
                    distro_version: UNKNOWN,
                    kernel_version: UNKNOWN,
                    environment_type: "unknown",
                    host_role: "unknown",
                    package_manager: "unknown",
                    cpu_count: 0,
                    memory_gb: 0,
                    installed_package_count: 0,
                    running_service_count: 0,
                }));
    }

    return cachedBaseMetadataPromise;
}

function normalizeIsoTimestamp(value: unknown): string {
    const candidate = toNonEmptyString(value);
    if (!candidate)
        return new Date().toISOString();

    const date = new Date(candidate);
    if (Number.isNaN(date.getTime()))
        return new Date().toISOString();

    return date.toISOString();
}

export async function createReportMetadata(options: CreateMetadataOptions): Promise<SecurityReportMetadata> {
    const base = await getBaseReportMetadata();

    return {
        scan_timestamp: normalizeIsoTimestamp(options.generatedAt),
        host_id: sanitizeString(base.host_id),
        distro: sanitizeString(base.distro),
        distro_version: sanitizeString(base.distro_version),
        kernel_version: sanitizeString(base.kernel_version),
        environment_type: base.environment_type,
        host_role: base.host_role,
        package_manager: options.packageManager || normalizePackageManager(base.package_manager),
        cpu_count: normalizeInteger(base.cpu_count),
        memory_gb: normalizeMemoryGb(base.memory_gb),
        installed_package_count: normalizeInteger(base.installed_package_count),
        running_service_count: normalizeInteger(base.running_service_count),
        scan_seconds: normalizeScanSeconds(options.scanSeconds),
        scanner_version: sanitizeString(options.scannerVersion),
        scanner_dataset_version: sanitizeString(options.scannerDatasetVersion),
    };
}
