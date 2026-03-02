/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import type { SecuritySeverity } from '../security-report';

export function getSeverityLabelColor(severity: SecuritySeverity) {
    if (severity === "critical")
        return "red" as const;
    if (severity === "high")
        return "orange" as const;
    if (severity === "medium")
        return "gold" as const;
    if (severity === "low")
        return "blue" as const;
    return "grey" as const;
}
