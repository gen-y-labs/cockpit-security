/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Nav, NavItem, NavList } from "@patternfly/react-core/dist/esm/components/Nav/index.js";

import cockpit from 'cockpit';

const _ = cockpit.gettext;

export type SecurityTab = 'updates' | 'vulnerabilities' | 'compliance';
const TABS: SecurityTab[] = ["updates", "vulnerabilities", "compliance"];

function isSecurityTab(value: unknown): value is SecurityTab {
    return value === "updates" || value === "vulnerabilities" || value === "compliance";
}

export function SecurityTabs({
    activeTab,
    onChange,
}: {
    activeTab: SecurityTab;
    onChange: (tab: SecurityTab) => void;
}) {
    const tabLabels: Record<SecurityTab, string> = {
        updates: _("Updates"),
        vulnerabilities: _("Vulnerabilities"),
        compliance: _("Compliance"),
    };

    return (
        <Nav
            variant="horizontal-subnav"
            id="services-filter"
            aria-label={_("Security providers navigation")}
            onSelect={(_event, result) => {
                if (!isSecurityTab(result.itemId))
                    return;

                const selectedTab = result.itemId;
                onChange(selectedTab);
            }}
        >
            <NavList>
                {TABS.map(tab => {
                    return (
                        <NavItem itemId={tab} key={tab} preventDefault isActive={activeTab === tab}>
                            <Button variant="link" component="a">{tabLabels[tab]}</Button>
                        </NavItem>
                    );
                })}
            </NavList>
        </Nav>
    );
}
