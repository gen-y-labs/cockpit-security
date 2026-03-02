/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import cockpit from "cockpit";

import type { SecurityProvider } from '../security-report';
import { NativeAptProvider } from './native-apt-provider';
import { NativeZypperProvider } from './native-zypper-provider';

interface OsReleaseInfo {
    id: string;
    idLike: string;
}

function parseOsRelease(content: string | null): OsReleaseInfo {
    let id = "";
    let idLike = "";

    if (!content)
        return { id, idLike };

    for (const line of content.split('\n')) {
        if (!line || line.startsWith('#'))
            continue;

        const separator = line.indexOf('=');
        if (separator < 0)
            continue;

        const key = line.slice(0, separator)
                .trim()
                .toUpperCase();
        const value = line.slice(separator + 1)
                .trim()
                .replace(/^"|"$/g, "")
                .toLowerCase();

        if (key === "ID")
            id = value;
        if (key === "ID_LIKE")
            idLike = value;
    }

    return { id, idLike };
}

function isAptBasedDistro(osInfo: OsReleaseInfo): boolean {
    return osInfo.id === "ubuntu" || osInfo.id === "debian" ||
           osInfo.idLike.includes("ubuntu") || osInfo.idLike.includes("debian");
}

export async function getNativeProvider(): Promise<SecurityProvider> {
    try {
        const osReleaseContent = await cockpit.file('/etc/os-release').read();
        const osInfo = parseOsRelease(osReleaseContent?.toString() || "");

        if (isAptBasedDistro(osInfo))
            return new NativeAptProvider();
    } catch {
        // Fall back to zypper provider to preserve openSUSE behavior.
    }

    return new NativeZypperProvider();
}
