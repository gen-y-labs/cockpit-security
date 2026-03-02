/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";

import cockpit from 'cockpit';

const _ = cockpit.gettext;

type SourceBadgeTone = "green" | "blue" | "purple" | "grey";

const SOURCE_LABELS: Record<string, string> = {
    "native-zypper": "native-zypper",
    "native-apt": "native-apt",
    trivy: "trivy",
};

const SOURCE_BADGE_COLORS: Record<string, SourceBadgeTone> = {
    "native-zypper": "green",
    "native-apt": "blue",
    trivy: "purple",
};

export function getSourceLabel(source: string) {
    return SOURCE_LABELS[source] || source;
}

export function SourceBadge({ source }: { source: string }) {
    const color = SOURCE_BADGE_COLORS[source] || "grey";

    return (
        <Label isCompact color={color}>
            {getSourceLabel(source)}
        </Label>
    );
}

export function SourceBadgeLegend({ sources }: { sources: string[] }) {
    if (sources.length === 0)
        return null;

    return (
        <Flex
            className="security-vulnerabilities__source-legend"
            spaceItems={{ default: "spaceItemsSm" }}
            alignItems={{ default: "alignItemsCenter" }}
        >
            <FlexItem>
                <Content component={ContentVariants.small} className="security-vulnerabilities__source-legend-label">
                    {_("Sources")}
                </Content>
            </FlexItem>
            {sources.map(source => (
                <FlexItem key={source}>
                    <SourceBadge source={source} />
                </FlexItem>
            ))}
        </Flex>
    );
}
