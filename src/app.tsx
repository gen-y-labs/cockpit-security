/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2017 Red Hat, Inc.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { EmptyState, EmptyStateBody } from "@patternfly/react-core/dist/esm/components/EmptyState/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import { Grid, GridItem } from "@patternfly/react-core/dist/esm/layouts/Grid/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { Nav, NavItem, NavList } from "@patternfly/react-core/dist/esm/components/Nav/index.js";
import { Page, PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { SearchInput } from "@patternfly/react-core/dist/esm/components/SearchInput/index.js";
import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";
import { SearchIcon } from "@patternfly/react-icons";

import cockpit from 'cockpit';
import type { SecurityReport, SecuritySeverity, SecuritySummary } from './security-report';
import { getNativeProvider } from './providers/native-provider';
import { getCachedTrivyReport, TrivyProvider, TRIVY_INSTALL_URL } from './providers/trivy-provider';
import { loadSystemInfo } from './system-info';

const _ = cockpit.gettext;

type VulnerabilityTab = 'native' | 'trivy';

function getOsAccentClass(osId: string, osName: string): string {
    const id = osId.toLowerCase();
    const name = osName.toLowerCase();

    if (id.includes("suse") || id.includes("sles") || name.includes("suse"))
        return "security-vulnerabilities--suse";
    if (id.includes("ubuntu") || id.includes("debian") || name.includes("ubuntu"))
        return "security-vulnerabilities--ubuntu";
    if (id.includes("rhel") || id.includes("fedora") || id.includes("centos"))
        return "security-vulnerabilities--rhel";

    return "";
}

function EmptyTabState({ title, body }: { title: string; body: string }) {
    return (
        <EmptyState className="security-vulnerabilities__empty-state" headingLevel="h2" titleText={title} icon={SearchIcon}>
            <EmptyStateBody>{body}</EmptyStateBody>
        </EmptyState>
    );
}

function getSeverityLabelColor(severity: SecuritySeverity) {
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

type SeverityFilter = 'all' | SecuritySeverity;

function createSummaryFromFindings(findings: SecurityReport["findings"]): SecuritySummary {
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

function SeverityCard({
    label,
    count,
    color,
    active,
    onClick,
}: {
    label: string;
    count: number;
    color: "red" | "orange" | "gold" | "blue" | "grey";
    active: boolean;
    onClick: () => void;
}) {
    return (
        <button type="button" className={`security-vulnerabilities__severity-card ${active ? "pf-m-active" : ""}`} onClick={onClick}>
            <Label color={color} isCompact>{label}</Label>
            <Content component={ContentVariants.h2}>{count.toString()}</Content>
        </button>
    );
}

interface NativeTabProps {
    loading: boolean;
    error: string | null;
    report: SecurityReport | null;
    lastUpdated: string;
    onRefresh: () => void;
    onDownloadJson: () => void;
    canDownload: boolean;
}

function NativeTabContent({ loading, error, report, lastUpdated, onRefresh, onDownloadJson, canDownload }: NativeTabProps) {
    const [searchFilter, setSearchFilter] = useState("");
    const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
    const [statusFilter, setStatusFilter] = useState("all");
    const [sourceFilter, setSourceFilter] = useState("all");

    const statusOptions = useMemo(() => {
        if (!report)
            return [];

        return [...new Set(report.findings.map(finding => finding.status))].sort();
    }, [report]);

    const sourceOptions = useMemo(() => {
        if (!report)
            return [];

        return [...new Set(report.findings.map(finding => finding.source))].sort();
    }, [report]);

    const filteredFindings = useMemo(() => {
        if (!report)
            return [];

        const search = searchFilter.trim().toLowerCase();

        return report.findings.filter(finding => {
            if (severityFilter !== "all" && finding.severity !== severityFilter)
                return false;
            if (statusFilter !== "all" && finding.status !== statusFilter)
                return false;
            if (sourceFilter !== "all" && finding.source !== sourceFilter)
                return false;
            if (!search)
                return true;

            return finding.id.toLowerCase().includes(search) ||
                finding.summary.toLowerCase().includes(search) ||
                finding.status.toLowerCase().includes(search) ||
                finding.source.toLowerCase().includes(search);
        });
    }, [report, searchFilter, severityFilter, statusFilter, sourceFilter]);

    const onClearAllFilters = () => {
        setSearchFilter("");
        setSeverityFilter("all");
        setStatusFilter("all");
        setSourceFilter("all");
    };

    if (loading) {
        return (
            <EmptyState className="security-vulnerabilities__empty-state" headingLevel="h2" titleText={_("Loading native security updates")} icon={Spinner}>
                <EmptyStateBody>{_("Running native security update query...")}</EmptyStateBody>
            </EmptyState>
        );
    }

    if (error) {
        return (
            <Alert className="security-vulnerabilities__alert" isInline variant="danger" title={_("Loading native security updates failed")}>
                <pre className="security-vulnerabilities__error">{error}</pre>
            </Alert>
        );
    }

    if (!report || report.findings.length === 0) {
        return (
            <EmptyTabState
                title={_("No native security patches found")}
                body={_("The native provider did not report any pending security patches.")}
            />
        );
    }

    const filteredSummary = createSummaryFromFindings(filteredFindings);
    return (
        <>
            <Flex className="security-vulnerabilities__tab-actions" justifyContent={{ default: "justifyContentFlexEnd" }} spaceItems={{ default: "spaceItemsSm" }}>
                <FlexItem>
                    <Content component={ContentVariants.small}>
                        {cockpit.format(_("Last updated: $0"), lastUpdated)}
                    </Content>
                </FlexItem>
                <FlexItem>
                    <Button variant="secondary" onClick={onRefresh} isDisabled={loading}>
                        {_("Refresh")}
                    </Button>
                </FlexItem>
                <FlexItem>
                    <Button variant="secondary" onClick={onDownloadJson} isDisabled={!canDownload}>
                        {_("Download JSON")}
                    </Button>
                </FlexItem>
            </Flex>
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

            <Toolbar
                clearAllFilters={onClearAllFilters}
                className="pf-m-sticky-top ct-compact services-toolbar security-vulnerabilities__filters-toolbar"
                numberOfFiltersText={n => cockpit.format(_("$0 filters applied"), n)}
            >
                <ToolbarContent>
                    <ToolbarItem>
                        <SearchInput
                            id="security-text-filter"
                            className="services-text-filter"
                            placeholder={_("Filter by package ID or summary")}
                            value={searchFilter}
                            onChange={(_event, value) => setSearchFilter(value)}
                            onClear={() => setSearchFilter("")}
                        />
                    </ToolbarItem>
                    <ToolbarItem>
                        <select className="pf-v6-c-form-control" value={severityFilter} onChange={event => setSeverityFilter(event.currentTarget.value as SeverityFilter)}>
                            <option value="all">{_("All severities")}</option>
                            <option value="critical">{_("Critical")}</option>
                            <option value="high">{_("High")}</option>
                            <option value="medium">{_("Medium")}</option>
                            <option value="low">{_("Low")}</option>
                            <option value="unknown">{_("Unknown")}</option>
                        </select>
                    </ToolbarItem>
                    <ToolbarItem>
                        <select className="pf-v6-c-form-control" value={statusFilter} onChange={event => setStatusFilter(event.currentTarget.value)}>
                            <option value="all">{_("All statuses")}</option>
                            {statusOptions.map(status => (
                                <option key={status} value={status}>{status}</option>
                            ))}
                        </select>
                    </ToolbarItem>
                    <ToolbarItem>
                        <select className="pf-v6-c-form-control" value={sourceFilter} onChange={event => setSourceFilter(event.currentTarget.value)}>
                            <option value="all">{_("All sources")}</option>
                            {sourceOptions.map(source => (
                                <option key={source} value={source}>{source}</option>
                            ))}
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
                    body={_("Try adjusting search text or filter selections.")}
                />
            )}
            {filteredFindings.length > 0 && (
                <div className="security-vulnerabilities__list-wrap">
                    <div className="security-vulnerabilities__totals">
                        {cockpit.format(_("C:$0 H:$1 M:$2 L:$3 Unknown:$4"), filteredSummary.critical, filteredSummary.high, filteredSummary.medium, filteredSummary.low, filteredSummary.unknown)}
                    </div>
                    <table className="pf-v6-c-table services-list security-vulnerabilities__list" aria-label={_("Native vulnerability findings")}>
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
                                                    {finding.severity}
                                                </Label>
                                            </FlexItem>
                                            <FlexItem>
                                                <Label isCompact color="grey">{finding.source}</Label>
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
    );
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

function TrivyTabContent({
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
            <Flex className="security-vulnerabilities__tab-actions" justifyContent={{ default: "justifyContentFlexEnd" }} spaceItems={{ default: "spaceItemsSm" }}>
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
            {loading && !report && (
                <EmptyState className="security-vulnerabilities__empty-state" headingLevel="h2" titleText={_("Running Trivy deep scan")} icon={Spinner}>
                    <EmptyStateBody>{_("Scanning the host filesystem with Trivy. This may take several minutes.")}</EmptyStateBody>
                </EmptyState>
            )}
            {error && (
                <Alert className="security-vulnerabilities__alert" isInline variant="danger" title={_("Deep scan failed")}>
                    {isMissingTrivyError
                        ? (
                            <Content component={ContentVariants.p}>
                                {_("Trivy is not installed on this system. Install Trivy with your package manager. Installation guide: ")}
                                <a href={TRIVY_INSTALL_URL} target="_blank" rel="noreferrer">{TRIVY_INSTALL_URL}</a>
                            </Content>
                        )
                        : (
                            <pre className="security-vulnerabilities__error">{error}</pre>
                        )}
                </Alert>
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
                                    placeholder={_("Filter by vulnerability ID or summary")}
                                    value={searchFilter}
                                    onChange={(_event, value) => setSearchFilter(value)}
                                    onClear={() => setSearchFilter("")}
                                />
                            </ToolbarItem>
                            <ToolbarItem>
                                <select className="pf-v6-c-form-control" value={severityFilter} onChange={event => setSeverityFilter(event.currentTarget.value as SeverityFilter)}>
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
                                                            {finding.severity}
                                                        </Label>
                                                    </FlexItem>
                                                    <FlexItem>
                                                        <Label isCompact color="grey">{finding.source}</Label>
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

export const Application = () => {
    const mountedRef = useRef(true);
    const [activeTab, setActiveTab] = useState<VulnerabilityTab>('native');
    const [osName, setOsName] = useState(_("Unknown"));
    const [osId, setOsId] = useState("");
    const [nativeLoading, setNativeLoading] = useState(true);
    const [nativeError, setNativeError] = useState<string | null>(null);
    const [nativeReport, setNativeReport] = useState<SecurityReport | null>(null);
    const [lastUpdated, setLastUpdated] = useState("--");
    const [trivyLoading, setTrivyLoading] = useState(false);
    const [trivyError, setTrivyError] = useState<string | null>(null);
    const [trivyReport, setTrivyReport] = useState<SecurityReport | null>(null);
    const [trivyLastUpdated, setTrivyLastUpdated] = useState("--");

    useEffect(() => {
        let mounted = true;

        loadSystemInfo().then(info => {
            if (!mounted)
                return;

            setOsName(info.osName);
            setOsId(info.osId);
        });

        return () => {
            mounted = false;
        };
    }, []);

    const loadNativeReport = useCallback(() => {
        if (!mountedRef.current)
            return Promise.resolve();

        setNativeLoading(true);
        setNativeError(null);

        return getNativeProvider()
                .then(provider => provider.getReport())
                .then(report => {
                    if (!mountedRef.current)
                        return;

                    setNativeReport(report);
                    setNativeError(null);
                    setLastUpdated(new Date(report.generatedAt).toLocaleString());
                })
                .catch(error => {
                    if (!mountedRef.current)
                        return;

                    setNativeError(error instanceof Error ? error.message : String(error));
                })
                .finally(() => {
                    if (mountedRef.current)
                        setNativeLoading(false);
                });
    }, []);

    useEffect(() => {
        loadNativeReport();
    }, [loadNativeReport]);

    useEffect(() => {
        return () => {
            mountedRef.current = false;
        };
    }, []);

    useEffect(() => {
        const cachedReport = getCachedTrivyReport();
        if (!cachedReport)
            return;

        setTrivyReport(cachedReport);
        setTrivyLastUpdated(new Date(cachedReport.generatedAt).toLocaleString());
    }, []);

    const osAccentClass = getOsAccentClass(osId, osName);

    const downloadReportJson = () => {
        if (!nativeReport)
            return;

        const blob = new Blob([JSON.stringify(nativeReport, null, 2)], { type: "application/json" });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `vulnerabilities-${nativeReport.provider}.json`;
        document.body.append(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
    };

    const runDeepScan = useCallback(() => {
        if (!mountedRef.current)
            return;

        setTrivyLoading(true);
        setTrivyError(null);

        new TrivyProvider().getReport()
                .then(report => {
                    if (!mountedRef.current)
                        return;

                    setTrivyReport(report);
                    setTrivyError(null);
                    setTrivyLastUpdated(new Date(report.generatedAt).toLocaleString());
                })
                .catch(error => {
                    if (!mountedRef.current)
                        return;

                    setTrivyError(error instanceof Error ? error.message : String(error));
                })
                .finally(() => {
                    if (mountedRef.current)
                        setTrivyLoading(false);
                });
    }, []);

    const downloadTrivyJson = () => {
        if (!trivyReport)
            return;

        const blob = new Blob([JSON.stringify(trivyReport, null, 2)], { type: "application/json" });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `vulnerabilities-${trivyReport.provider}.json`;
        document.body.append(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
    };

    const activeTabContent = activeTab === "native"
        ? (
            <Card className="security-vulnerabilities__panel">
                <CardBody>
                    <NativeTabContent
                        loading={nativeLoading}
                        error={nativeError}
                        report={nativeReport}
                        lastUpdated={lastUpdated}
                        onRefresh={loadNativeReport}
                        onDownloadJson={downloadReportJson}
                        canDownload={nativeReport !== null}
                    />
                </CardBody>
            </Card>
        )
        : (
            <Card className="security-vulnerabilities__panel">
                <CardBody>
                    <TrivyTabContent
                        loading={trivyLoading}
                        error={trivyError}
                        report={trivyReport}
                        lastUpdated={trivyLastUpdated}
                        onRunScan={runDeepScan}
                        onDownloadJson={downloadTrivyJson}
                        canDownload={trivyReport !== null}
                    />
                </CardBody>
            </Card>
        );

    return (
        <Page className={`pf-m-no-sidebar security-vulnerabilities ${osAccentClass}`.trim()}>
            <PageSection hasBodyWrapper={false}>
                <Nav
                    variant="horizontal-subnav"
                    className="security-vulnerabilities__tabs"
                    aria-label={_("Vulnerability providers navigation")}
                    onSelect={(_event, result) => setActiveTab(result.itemId as VulnerabilityTab)}
                >
                    <NavList>
                        <NavItem itemId="native" preventDefault isActive={activeTab === "native"}>
                            <Button variant="link" component="a">{_("Native")}</Button>
                        </NavItem>
                        <NavItem itemId="trivy" preventDefault isActive={activeTab === "trivy"}>
                            <Button variant="link" component="a">{_("Trivy")}</Button>
                        </NavItem>
                    </NavList>
                </Nav>
                {activeTabContent}
            </PageSection>
        </Page>
    );
};
