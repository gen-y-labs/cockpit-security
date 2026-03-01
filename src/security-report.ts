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

export interface SecurityReport {
    provider: string;
    generatedAt: string;
    findings: SecurityFinding[];
    summary: SecuritySummary;
}

export interface SecurityProvider {
    getReport(): Promise<SecurityReport>;
}
