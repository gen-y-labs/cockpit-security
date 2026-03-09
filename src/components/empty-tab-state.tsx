/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import { EmptyState, EmptyStateBody } from "@patternfly/react-core/dist/esm/components/EmptyState/index.js";
import { SearchIcon } from "@patternfly/react-icons";

export function EmptyTabState({ title, body }: { title: string; body: string }) {
    return (
        <EmptyState className="security-vulnerabilities__empty-state" headingLevel="h2" titleText={title} icon={SearchIcon}>
            <EmptyStateBody>{body}</EmptyStateBody>
        </EmptyState>
    );
}
