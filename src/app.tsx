/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2017 Red Hat, Inc.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import { Page, PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";

import cockpit from 'cockpit';
import { SecurityTabs } from './components/security-tabs';
import type { SecurityTab } from './components/security-tabs';
import { getNativeProvider } from './providers/native-provider';
import { getCachedOpenScapReport, listOpenScapSources, OpenScapProvider } from './providers/openscap-provider';
import { getCachedTrivyReport, TrivyProvider } from './providers/trivy-provider';
import type { SecurityReport } from './security-report';
import { loadSystemInfo } from './system-info';
import { ComplianceTabContent } from './tabs/compliance-tab-content';
import { UpdatesTabContent } from './tabs/updates-tab-content';
import { VulnerabilitiesTabContent } from './tabs/vulnerabilities-tab-content';

const _ = cockpit.gettext;

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

function downloadReportJson(report: SecurityReport | null) {
    if (!report)
        return;

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `vulnerabilities-${report.provider}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
}

export const Application = () => {
    const mountedRef = useRef(true);
    const [activeTab, setActiveTab] = useState<SecurityTab>('updates');
    const [osName, setOsName] = useState(_("Unknown"));
    const [osId, setOsId] = useState("");
    const [updatesLoading, setUpdatesLoading] = useState(true);
    const [updatesError, setUpdatesError] = useState<string | null>(null);
    const [updatesReport, setUpdatesReport] = useState<SecurityReport | null>(null);
    const [lastUpdated, setLastUpdated] = useState("--");
    const [vulnerabilitiesLoading, setVulnerabilitiesLoading] = useState(false);
    const [vulnerabilitiesError, setVulnerabilitiesError] = useState<string | null>(null);
    const [vulnerabilitiesReport, setVulnerabilitiesReport] = useState<SecurityReport | null>(null);
    const [vulnerabilitiesLastUpdated, setVulnerabilitiesLastUpdated] = useState("--");
    const [complianceLoading, setComplianceLoading] = useState(false);
    const [complianceLoadingSources, setComplianceLoadingSources] = useState(true);
    const [complianceError, setComplianceError] = useState<string | null>(null);
    const [complianceReport, setComplianceReport] = useState<SecurityReport | null>(null);
    const [complianceLastUpdated, setComplianceLastUpdated] = useState("--");
    const [complianceSources, setComplianceSources] = useState<string[]>([]);
    const [selectedComplianceSource, setSelectedComplianceSource] = useState("");

    useEffect(() => {
        let mounted = true;

        loadSystemInfo()
                .then(info => {
                    if (!mounted)
                        return;

                    setOsName(info.osName);
                    setOsId(info.osId);
                })
                .catch(() => {
                    if (!mounted)
                        return;

                    setOsName(_("Unknown"));
                    setOsId("");
                });

        return () => {
            mounted = false;
        };
    }, []);

    const loadUpdatesReport = useCallback(() => {
        if (!mountedRef.current)
            return Promise.resolve();

        setUpdatesLoading(true);
        setUpdatesError(null);

        return getNativeProvider()
                .then(provider => provider.getReport())
                .then(report => {
                    if (!mountedRef.current)
                        return;

                    setUpdatesReport(report);
                    setUpdatesError(null);
                    setLastUpdated(new Date(report.generatedAt).toLocaleString());
                })
                .catch(error => {
                    if (!mountedRef.current)
                        return;

                    setUpdatesError(error instanceof Error ? error.message : String(error));
                })
                .finally(() => {
                    if (mountedRef.current)
                        setUpdatesLoading(false);
                });
    }, []);

    useEffect(() => {
        loadUpdatesReport();
    }, [loadUpdatesReport]);

    useEffect(() => {
        return () => {
            mountedRef.current = false;
        };
    }, []);

    useEffect(() => {
        const cachedReport = getCachedTrivyReport();
        if (!cachedReport)
            return;

        setVulnerabilitiesReport(cachedReport);
        setVulnerabilitiesLastUpdated(new Date(cachedReport.generatedAt).toLocaleString());
    }, []);

    useEffect(() => {
        const cachedReport = getCachedOpenScapReport();
        if (!cachedReport)
            return;

        setComplianceReport(cachedReport);
        setComplianceLastUpdated(new Date(cachedReport.generatedAt).toLocaleString());
    }, []);

    useEffect(() => {
        setComplianceLoadingSources(true);
        listOpenScapSources()
                .then(sources => {
                    if (!mountedRef.current)
                        return;

                    setComplianceSources(sources);
                    setSelectedComplianceSource(previous => previous || sources[0] || "");
                })
                .catch(error => {
                    if (!mountedRef.current)
                        return;

                    setComplianceError(error instanceof Error ? error.message : String(error));
                })
                .finally(() => {
                    if (mountedRef.current)
                        setComplianceLoadingSources(false);
                });
    }, []);

    const runVulnerabilityScan = useCallback(() => {
        if (!mountedRef.current)
            return;

        setVulnerabilitiesLoading(true);
        setVulnerabilitiesError(null);

        new TrivyProvider().getReport()
                .then(report => {
                    if (!mountedRef.current)
                        return;

                    setVulnerabilitiesReport(report);
                    setVulnerabilitiesError(null);
                    setVulnerabilitiesLastUpdated(new Date(report.generatedAt).toLocaleString());
                })
                .catch(error => {
                    if (!mountedRef.current)
                        return;

                    setVulnerabilitiesError(error instanceof Error ? error.message : String(error));
                })
                .finally(() => {
                    if (mountedRef.current)
                        setVulnerabilitiesLoading(false);
                });
    }, []);

    const runComplianceScan = useCallback(() => {
        if (!mountedRef.current || !selectedComplianceSource)
            return;

        setComplianceLoading(true);
        setComplianceError(null);

        new OpenScapProvider({ source: selectedComplianceSource }).getReport()
                .then(report => {
                    if (!mountedRef.current)
                        return;

                    setComplianceReport(report);
                    setComplianceError(null);
                    setComplianceLastUpdated(new Date(report.generatedAt).toLocaleString());
                })
                .catch(error => {
                    if (!mountedRef.current)
                        return;

                    setComplianceError(error instanceof Error ? error.message : String(error));
                })
                .finally(() => {
                    if (mountedRef.current)
                        setComplianceLoading(false);
                });
    }, [selectedComplianceSource]);

    const osAccentClass = getOsAccentClass(osId, osName);

    let activeTabContent;
    if (activeTab === "updates") {
        activeTabContent = (
            <section className="security-vulnerabilities__panel">
                <UpdatesTabContent
                    loading={updatesLoading}
                    error={updatesError}
                    report={updatesReport}
                    lastUpdated={lastUpdated}
                    onRefresh={loadUpdatesReport}
                    onDownloadJson={() => downloadReportJson(updatesReport)}
                    canDownload={updatesReport !== null}
                />
            </section>
        );
    } else if (activeTab === "vulnerabilities") {
        activeTabContent = (
            <section className="security-vulnerabilities__panel">
                <VulnerabilitiesTabContent
                    loading={vulnerabilitiesLoading}
                    error={vulnerabilitiesError}
                    report={vulnerabilitiesReport}
                    lastUpdated={vulnerabilitiesLastUpdated}
                    onRunScan={runVulnerabilityScan}
                    onDownloadJson={() => downloadReportJson(vulnerabilitiesReport)}
                    canDownload={vulnerabilitiesReport !== null}
                />
            </section>
        );
    } else {
        activeTabContent = (
            <section className="security-vulnerabilities__panel">
                <ComplianceTabContent
                    loading={complianceLoading}
                    loadingSources={complianceLoadingSources}
                    error={complianceError}
                    report={complianceReport}
                    lastUpdated={complianceLastUpdated}
                    selectedSource={selectedComplianceSource}
                    sources={complianceSources}
                    onSourceChange={setSelectedComplianceSource}
                    onRunScan={runComplianceScan}
                    onDownloadJson={() => downloadReportJson(complianceReport)}
                    canDownload={complianceReport !== null}
                />
            </section>
        );
    }

    return (
        <Page className={`pf-m-no-sidebar security-vulnerabilities ${osAccentClass}`.trim()}>
            <PageSection hasBodyWrapper={false}>
                <SecurityTabs activeTab={activeTab} onChange={setActiveTab} />
                {activeTabContent}
            </PageSection>
        </Page>
    );
};
