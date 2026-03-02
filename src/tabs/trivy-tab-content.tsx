/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import { useMemo, useState } from 'react';

import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { EmptyState, EmptyStateBody } from "@patternfly/react-core/dist/esm/components/EmptyState/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import { Grid, GridItem } from "@patternfly/react-core/dist/esm/layouts/Grid/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { SearchInput } from "@patternfly/react-core/dist/esm/components/SearchInput/index.js";
import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";

import cockpit from 'cockpit';
import { EmptyTabState } from '../components/empty-tab-state';
import { ErrorBanner } from '../components/error-banner';
import { SeverityCard } from '../components/severity-card';
import { SourceBadge, SourceBadgeLegend } from '../components/source-badge';
import { TRIVY_INSTALL_URL } from '../providers/trivy-provider';
import type { SecurityReport, SecuritySeverity } from '../security-report';
import { createSummaryFromFindings } from '../utils/findings';
import { getSeverityLabelColor } from '../utils/severity';

const _ = cockpit.gettext;

type SeverityFilter = 'all' | SecuritySeverity;

function getSeverityText(severity: SecuritySeverity) {
    if (severity === "critical")
        return _("Critical");
    if (severity === "high")
        return _("High");
    if (severity === "medium")
        return _("Medium");
    if (severity === "low")
        return _("Low");
    return _("Unknown");
}

interface TrivyTabProps {
    loading: boolean;
    error: string | null;
    report: SecurityReport | null;
    lastUpdated: string;
    onRunScan: () => void;
    onDownloadJson: () => void;
    canDownload: boolean;
}

export function TrivyTabContent({
    loading,
    error,
    report,
    lastUpdated,
    onRunScan,
    onDownloadJson,
    canDownload
}: TrivyTabProps) {
    const [searchFilter, setSearchFilter] = useState("");
    const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");

    const filteredFindings = useMemo(() => {
        if (!report)
            return [];

        const search = searchFilter.trim().toLowerCase();

        return report.findings.filter(finding => {
            if (severityFilter !== "all" && finding.severity !== severityFilter)
                return false;
            if (!search)
                return true;

            return finding.id.toLowerCase().includes(search) ||
                finding.summary.toLowerCase().includes(search) ||
                finding.status.toLowerCase().includes(search) ||
                finding.source.toLowerCase().includes(search);
        });
    }, [report, searchFilter, severityFilter]);

    const filteredSummary = useMemo(() => createSummaryFromFindings(filteredFindings), [filteredFindings]);
    const isMissingTrivyError = error?.includes(TRIVY_INSTALL_URL) || false;

    return (
        <>
            <Flex className="security-vulnerabilities__header-controls" justifyContent={{ default: "justifyContentSpaceBetween" }} alignItems={{ default: "alignItemsCenter" }}>
                <FlexItem>
                    <SourceBadgeLegend sources={["trivy"]} />
                </FlexItem>
                <FlexItem>
                    <Flex className="security-vulnerabilities__tab-actions" spaceItems={{ default: "spaceItemsSm" }} alignItems={{ default: "alignItemsCenter" }}>
                        <FlexItem>
                            <Content component={ContentVariants.small}>
                                {cockpit.format(_("Last deep scan: $0"), lastUpdated)}
                            </Content>
                        </FlexItem>
                        <FlexItem>
                            <Button variant="primary" onClick={onRunScan} isLoading={loading}>
                                {_("Run Deep Scan")}
                            </Button>
                        </FlexItem>
                        <FlexItem>
                            <Button variant="secondary" onClick={onDownloadJson} isDisabled={!canDownload}>
                                {_("Download JSON")}
                            </Button>
                        </FlexItem>
                    </Flex>
                </FlexItem>
            </Flex>
            {loading && !report && (
                <EmptyState className="security-vulnerabilities__empty-state" headingLevel="h2" titleText={_("Running Trivy deep scan")} icon={Spinner}>
                    <EmptyStateBody>{_("Scanning the host filesystem with Trivy. This may take several minutes.")}</EmptyStateBody>
                </EmptyState>
            )}
            {error && (
                <ErrorBanner title={_("Deep scan failed")} error={error}>
                    {isMissingTrivyError
                        ? (
                            <Content component={ContentVariants.p}>
                                {_("Trivy is not installed on this system. Install Trivy with your package manager. Installation guide: ")}
                                <a href={TRIVY_INSTALL_URL} target="_blank" rel="noreferrer">{TRIVY_INSTALL_URL}</a>
                            </Content>
                        )
                        : undefined}
                </ErrorBanner>
            )}
            {!loading && !error && !report && (
                <EmptyTabState
                    title={_("No deep scan results yet")}
                    body={_("Run a Trivy deep scan to collect vulnerability findings for this host.")}
                />
            )}
            {!loading && !error && report && report.findings.length === 0 && (
                <EmptyTabState
                    title={_("No deep scan vulnerabilities found")}
                    body={_("Trivy did not report any vulnerabilities for this scan.")}
                />
            )}
            {report && report.findings.length > 0 && (
                <>
                    <Grid hasGutter className="security-vulnerabilities__severity-grid">
                        <GridItem md={2}>
                            <SeverityCard
                                label={_("All")}
                                count={report.summary.total}
                                color="grey"
                                active={severityFilter === "all"}
                                onClick={() => setSeverityFilter("all")}
                            />
                        </GridItem>
                        <GridItem md={2}>
                            <SeverityCard
                                label={_("Critical")}
                                count={report.summary.critical}
                                color="red"
                                active={severityFilter === "critical"}
                                onClick={() => setSeverityFilter(prev => prev === "critical" ? "all" : "critical")}
                            />
                        </GridItem>
                        <GridItem md={2}>
                            <SeverityCard
                                label={_("High")}
                                count={report.summary.high}
                                color="orange"
                                active={severityFilter === "high"}
                                onClick={() => setSeverityFilter(prev => prev === "high" ? "all" : "high")}
                            />
                        </GridItem>
                        <GridItem md={2}>
                            <SeverityCard
                                label={_("Medium")}
                                count={report.summary.medium}
                                color="gold"
                                active={severityFilter === "medium"}
                                onClick={() => setSeverityFilter(prev => prev === "medium" ? "all" : "medium")}
                            />
                        </GridItem>
                        <GridItem md={2}>
                            <SeverityCard
                                label={_("Low")}
                                count={report.summary.low}
                                color="blue"
                                active={severityFilter === "low"}
                                onClick={() => setSeverityFilter(prev => prev === "low" ? "all" : "low")}
                            />
                        </GridItem>
                    </Grid>
                    <Toolbar className="pf-m-sticky-top ct-compact services-toolbar security-vulnerabilities__filters-toolbar">
                        <ToolbarContent>
                            <ToolbarItem>
                                <SearchInput
                                    id="trivy-text-filter"
                                    className="services-text-filter"
                                    aria-label={_("Filter findings by vulnerability ID or summary")}
                                    placeholder={_("Filter by vulnerability ID or summary")}
                                    value={searchFilter}
                                    onChange={(_event, value) => setSearchFilter(value)}
                                    onClear={() => setSearchFilter("")}
                                />
                            </ToolbarItem>
                            <ToolbarItem>
                                <select className="pf-v6-c-form-control" aria-label={_("Filter by severity")} value={severityFilter} onChange={event => setSeverityFilter(event.currentTarget.value as SeverityFilter)}>
                                    <option value="all">{_("All severities")}</option>
                                    <option value="critical">{_("Critical")}</option>
                                    <option value="high">{_("High")}</option>
                                    <option value="medium">{_("Medium")}</option>
                                    <option value="low">{_("Low")}</option>
                                    <option value="unknown">{_("Unknown")}</option>
                                </select>
                            </ToolbarItem>
                        </ToolbarContent>
                    </Toolbar>
                    <Content className="security-vulnerabilities__filtered-summary" component={ContentVariants.small}>
                        {cockpit.format(_("Showing $0 of $1 findings"), filteredFindings.length, report.summary.total)}
                    </Content>
                    {filteredFindings.length === 0 && (
                        <EmptyTabState
                            title={_("No matching findings")}
                            body={_("Try adjusting search text or severity filter.")}
                        />
                    )}
                    {filteredFindings.length > 0 && (
                        <div className="security-vulnerabilities__list-wrap">
                            <div className="security-vulnerabilities__totals">
                                {cockpit.format(_("C:$0 H:$1 M:$2 L:$3 Unknown:$4"), filteredSummary.critical, filteredSummary.high, filteredSummary.medium, filteredSummary.low, filteredSummary.unknown)}
                            </div>
                            <table className="pf-v6-c-table services-list security-vulnerabilities__list" aria-label={_("Trivy vulnerability findings")}>
                                <tbody>
                                    {filteredFindings.map(finding => (
                                        <tr key={`${finding.id}-${finding.source}-${finding.status}`}>
                                            <td className="security-vulnerabilities__finding-main-cell">
                                                <div className="security-vulnerabilities__finding-inline">
                                                    <span className="security-vulnerabilities__id">{finding.id}</span>
                                                    <span className="security-vulnerabilities__finding-summary">{finding.summary}</span>
                                                </div>
                                            </td>
                                            <td className="security-vulnerabilities__finding-meta-cell">
                                                <Flex spaceItems={{ default: "spaceItemsSm" }} alignItems={{ default: "alignItemsCenter" }} className="security-vulnerabilities__finding-meta">
                                                    <FlexItem>
                                                        <Label isCompact color={getSeverityLabelColor(finding.severity)}>
                                                            {getSeverityText(finding.severity)}
                                                        </Label>
                                                    </FlexItem>
                                                    <FlexItem>
                                                        <SourceBadge source={finding.source} />
                                                    </FlexItem>
                                                    <FlexItem>
                                                        <Label isCompact color="grey">{finding.status}</Label>
                                                    </FlexItem>
                                                </Flex>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </>
            )}
        </>
    );
}
