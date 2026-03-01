/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2017 Red Hat, Inc.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';

import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { Content, ContentVariants } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { EmptyState, EmptyStateBody } from "@patternfly/react-core/dist/esm/components/EmptyState/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { List, ListItem } from "@patternfly/react-core/dist/esm/components/List/index.js";
import { Page, PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { Tab, Tabs } from "@patternfly/react-core/dist/esm/components/Tabs/index.js";
import { SearchIcon } from "@patternfly/react-icons";

import cockpit from 'cockpit';
import type { SecurityReport, SecuritySeverity, SecuritySummary } from './security-report';
import { getNativeProvider } from './providers/native-provider';
import { loadSystemInfo } from './system-info';

const _ = cockpit.gettext;

type VulnerabilityTab = 'native' | 'trivy';

const EMPTY_SUMMARY: SecuritySummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    total: 0,
};

interface SummaryHeaderProps {
    hostname: string;
    osName: string;
    lastUpdated: string;
    counts: SecuritySummary;
    loading: boolean;
    onRefresh: () => void;
    onDownloadJson: () => void;
    canDownload: boolean;
}

function getStatusPill(counts: SecuritySummary) {
    if (counts.critical > 0)
        return { color: "red" as const, text: _("Critical vulnerabilities") };
    if (counts.high > 0)
        return { color: "orange" as const, text: _("High vulnerabilities") };
    if (counts.medium > 0)
        return { color: "gold" as const, text: _("Medium vulnerabilities") };
    if (counts.low > 0)
        return { color: "blue" as const, text: _("Low vulnerabilities") };
    if (counts.unknown > 0)
        return { color: "grey" as const, text: _("Unknown severity") };

    return { color: "green" as const, text: _("No pending vulnerabilities") };
}

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

function SummaryHeader({
    hostname,
    osName,
    lastUpdated,
    counts,
    loading,
    onRefresh,
    onDownloadJson,
    canDownload,
}: SummaryHeaderProps) {
    const status = getStatusPill(counts);

    return (
        <Card isPlain className="security-vulnerabilities__header">
            <CardTitle>
                <Flex justifyContent={{ default: "justifyContentSpaceBetween" }} alignItems={{ default: "alignItemsCenter" }}>
                    <FlexItem>
                        <Content component={ContentVariants.h1}>{_("Vulnerabilities")}</Content>
                    </FlexItem>
                    <FlexItem>
                        <Flex spaceItems={{ default: "spaceItemsSm" }} alignItems={{ default: "alignItemsCenter" }}>
                            <FlexItem>
                                <Label color={status.color} isCompact>{status.text}</Label>
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
                    </FlexItem>
                </Flex>
            </CardTitle>
            <CardBody>
                <div className="security-vulnerabilities__system-info">
                    <Content component={ContentVariants.small}>
                        {cockpit.format(_("Host: $0"), hostname)}
                    </Content>
                    <Content component={ContentVariants.small}>
                        {cockpit.format(_("OS: $0"), osName)}
                    </Content>
                    <Content component={ContentVariants.small}>
                        {cockpit.format(_("Last updated: $0"), lastUpdated)}
                    </Content>
                </div>
                <div className="security-vulnerabilities__count-list" role="list" aria-label={_("Vulnerability summary") }>
                    <Label color="red" isCompact role="listitem">{cockpit.format(_("Critical: $0"), counts.critical)}</Label>
                    <Label color="orange" isCompact role="listitem">{cockpit.format(_("High: $0"), counts.high)}</Label>
                    <Label color="gold" isCompact role="listitem">{cockpit.format(_("Medium: $0"), counts.medium)}</Label>
                    <Label color="blue" isCompact role="listitem">{cockpit.format(_("Low: $0"), counts.low)}</Label>
                </div>
            </CardBody>
        </Card>
    );
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

interface NativeTabProps {
    loading: boolean;
    error: string | null;
    report: SecurityReport | null;
}

function NativeTabContent({ loading, error, report }: NativeTabProps) {
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

    return (
        <>
            <Content component={ContentVariants.p}>
                {cockpit.format(_("Found $0 native security patches."), report.summary.total)}
            </Content>
            <List className="security-vulnerabilities__findings">
                {report.findings.map(finding => (
                    <ListItem key={finding.id} className="security-vulnerabilities__finding-item">
                        <Flex justifyContent={{ default: "justifyContentSpaceBetween" }} alignItems={{ default: "alignItemsCenter" }}>
                            <FlexItem>
                                <Content component={ContentVariants.small}>
                                    {finding.id}
                                </Content>
                            </FlexItem>
                            <FlexItem>
                                <Label isCompact color={getSeverityLabelColor(finding.severity)}>
                                    {finding.severity}
                                </Label>
                            </FlexItem>
                        </Flex>
                        <Content component={ContentVariants.small}>
                            {finding.summary}
                        </Content>
                    </ListItem>
                ))}
            </List>
        </>
    );
}

export const Application = () => {
    const mountedRef = useRef(true);
    const [activeTab, setActiveTab] = useState<VulnerabilityTab>('native');
    const [hostname, setHostname] = useState(_("Unknown"));
    const [osName, setOsName] = useState(_("Unknown"));
    const [osId, setOsId] = useState("");
    const [nativeLoading, setNativeLoading] = useState(true);
    const [nativeError, setNativeError] = useState<string | null>(null);
    const [nativeReport, setNativeReport] = useState<SecurityReport | null>(null);
    const [lastUpdated, setLastUpdated] = useState("--");

    useEffect(() => {
        let mounted = true;

        loadSystemInfo().then(info => {
            if (!mounted)
                return;

            setHostname(info.hostname);
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

    const summaryCounts = nativeReport?.summary || EMPTY_SUMMARY;
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

    return (
        <Page className={`pf-m-no-sidebar security-vulnerabilities ${osAccentClass}`.trim()}>
            <PageSection hasBodyWrapper={false}>
                <SummaryHeader
                    hostname={hostname}
                    osName={osName}
                    lastUpdated={lastUpdated}
                    counts={summaryCounts}
                    loading={nativeLoading}
                    onRefresh={loadNativeReport}
                    onDownloadJson={downloadReportJson}
                    canDownload={nativeReport !== null}
                />
            </PageSection>
            <PageSection hasBodyWrapper={false}>
                <Tabs
                    className="security-vulnerabilities__tabs"
                    activeKey={activeTab}
                    onSelect={(_event, tabKey) => setActiveTab(tabKey as VulnerabilityTab)}
                    aria-label={_("Vulnerability providers")}
                >
                    <Tab eventKey="native" title={_("Native")}>
                        <Card className="security-vulnerabilities__panel">
                            <CardBody>
                                <NativeTabContent loading={nativeLoading} error={nativeError} report={nativeReport} />
                            </CardBody>
                        </Card>
                    </Tab>
                    <Tab eventKey="trivy" title={_("Trivy")}>
                        <Card className="security-vulnerabilities__panel">
                            <CardBody>
                                <EmptyTabState
                                    title={_("No deep scan results yet")}
                                    body={_("Trivy scan integration will appear here in a later phase.")}
                                />
                            </CardBody>
                        </Card>
                    </Tab>
                </Tabs>
            </PageSection>
        </Page>
    );
};
