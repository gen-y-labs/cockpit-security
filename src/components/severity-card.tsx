/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";

export function SeverityCard({
    label,
    count,
    color,
    active,
    onClick,
}: {
    label: string;
    count: number;
    color: "red" | "orange" | "yellow" | "blue" | "grey";
    active: boolean;
    onClick: () => void;
}) {
    return (
        <button
            type="button"
            className={`security-vulnerabilities__severity-card ${active ? "pf-m-active" : ""}`}
            onClick={onClick}
            aria-pressed={active}
        >
            <Label color={color} isCompact>{label}</Label>
            <Content component={ContentVariants.h2}>{count.toString()}</Content>
        </button>
    );
}
