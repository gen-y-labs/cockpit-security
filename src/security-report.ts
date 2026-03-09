/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface SecurityFinding {
    id: string;
    summary: string;
    severity: SecuritySeverity;
    status: string;
    source: string;
}

export interface SecuritySummary {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
    total: number;
}

export type EnvironmentType = 'vm' | 'cloud-vm' | 'bare-metal' | 'unknown';
export type HostRole = 'minimal' | 'web-server' | 'db-server' | 'container-host' | 'generic' | 'unknown';
export type PackageManager = 'apt' | 'dnf' | 'zypper' | 'unknown';

export interface SecurityReportMetadata {
    scan_timestamp: string;
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
    scan_seconds: number;
    scanner_version: string;
    scanner_dataset_version: string;
}

export interface SecurityReport {
    provider: string;
    generatedAt: string;
    findings: SecurityFinding[];
    summary: SecuritySummary;
    metadata?: SecurityReportMetadata;
}

export interface SecurityProvider {
    getReport(): Promise<SecurityReport>;
}
