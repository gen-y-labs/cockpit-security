/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import cockpit from "cockpit";

import type { SecurityProvider } from '../security-report';
import { NativeAptProvider } from './native-apt-provider';
import { NativeDnfProvider } from './native-dnf-provider';
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

function isDnfBasedDistro(osInfo: OsReleaseInfo): boolean {
    const fingerprint = `${osInfo.id} ${osInfo.idLike}`;
    return fingerprint.includes("fedora") ||
           fingerprint.includes("rhel") ||
           fingerprint.includes("centos") ||
           fingerprint.includes("rocky") ||
           fingerprint.includes("almalinux") ||
           fingerprint.includes("amzn");
}

async function commandExists(command: string): Promise<boolean> {
    try {
        const output = await cockpit.spawn(["/bin/sh", "-ec", `command -v ${command} >/dev/null 2>&1 && echo yes || true`]);
        return output.trim() === "yes";
    } catch {
        return false;
    }
}

export async function getNativeProvider(): Promise<SecurityProvider> {
    try {
        const osReleaseContent = await cockpit.file('/etc/os-release').read();
        const osInfo = parseOsRelease(osReleaseContent?.toString() || "");

        if (isAptBasedDistro(osInfo))
            return new NativeAptProvider();
        if (isDnfBasedDistro(osInfo))
            return new NativeDnfProvider();
    } catch {
        // Fall through to command-based detection.
    }

    if (await commandExists("apt-get"))
        return new NativeAptProvider();
    if (await commandExists("dnf"))
        return new NativeDnfProvider();

    return new NativeZypperProvider();
}
