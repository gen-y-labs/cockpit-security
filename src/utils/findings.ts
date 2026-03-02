/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import type { SecurityReport, SecuritySummary } from '../security-report';

export function createSummaryFromFindings(findings: SecurityReport["findings"]): SecuritySummary {
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
