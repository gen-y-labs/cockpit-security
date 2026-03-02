/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import type { ReactNode } from 'react';

import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";

export function ErrorBanner({
    title,
    error,
    children,
}: {
    title: string;
    error?: string;
    children?: ReactNode;
}) {
    return (
        <Alert className="security-vulnerabilities__alert" isInline variant="danger" title={title}>
            {children || <pre className="security-vulnerabilities__error">{error}</pre>}
        </Alert>
    );
}
