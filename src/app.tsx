/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2017 Red Hat, Inc.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import { Page, PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";

import cockpit from 'cockpit';
import { VulnerabilityTabs } from './components/vulnerability-tabs';
import type { VulnerabilityTab } from './components/vulnerability-tabs';
import { getNativeProvider } from './providers/native-provider';
import { getCachedOpenScapReport, listOpenScapSources, OpenScapProvider } from './providers/openscap-provider';
import { getCachedTrivyReport, TrivyProvider } from './providers/trivy-provider';
import type { SecurityReport } from './security-report';
import { loadSystemInfo } from './system-info';
import { ComplianceTabContent } from './tabs/compliance-tab-content';
import { NativeTabContent } from './tabs/native-tab-content';
import { TrivyTabContent } from './tabs/trivy-tab-content';

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
    if (activeTab === "native") {
        activeTabContent = (
            <section className="security-vulnerabilities__panel">
                <NativeTabContent
                    loading={nativeLoading}
                    error={nativeError}
                    report={nativeReport}
                    lastUpdated={lastUpdated}
                    onRefresh={loadNativeReport}
                    onDownloadJson={() => downloadReportJson(nativeReport)}
                    canDownload={nativeReport !== null}
                />
            </section>
        );
    } else if (activeTab === "trivy") {
        activeTabContent = (
            <section className="security-vulnerabilities__panel">
                <TrivyTabContent
                    loading={trivyLoading}
                    error={trivyError}
                    report={trivyReport}
                    lastUpdated={trivyLastUpdated}
                    onRunScan={runDeepScan}
                    onDownloadJson={() => downloadReportJson(trivyReport)}
                    canDownload={trivyReport !== null}
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
                <VulnerabilityTabs activeTab={activeTab} onChange={setActiveTab} />
                {activeTabContent}
            </PageSection>
        </Page>
    );
};
