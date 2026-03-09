/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import cockpit from "cockpit";

const UNKNOWN = cockpit.gettext("Unknown");

export interface SystemInfo {
    hostname: string;
    osName: string;
    osId: string;
}

function unquote(value: string): string {
    if (value.startsWith('"') && value.endsWith('"'))
        return value.slice(1, -1);
    return value;
}

function parseOsRelease(content: string | null): Record<string, string> {
    const fields: Record<string, string> = {};
    if (!content)
        return fields;

    for (const line of content.split('\n')) {
        if (!line || line.startsWith('#'))
            continue;

        const separator = line.indexOf('=');
        if (separator < 0)
            continue;

        const key = line.slice(0, separator).trim();
        const value = unquote(line.slice(separator + 1).trim());
        fields[key] = value;
    }

    return fields;
}

async function readFileTrimmed(path: string): Promise<string> {
    try {
        const content = await cockpit.file(path).read();
        return content?.toString().trim() || "";
    } catch {
        return "";
    }
}

export async function loadSystemInfo(): Promise<SystemInfo> {
    const [hostname, osReleaseContent] = await Promise.all([
        readFileTrimmed('/etc/hostname'),
        readFileTrimmed('/etc/os-release'),
    ]);

    const osRelease = parseOsRelease(osReleaseContent);
    const osName = osRelease.PRETTY_NAME || osRelease.NAME || UNKNOWN;
    const osId = (osRelease.ID || "").toLowerCase();

    return {
        hostname: hostname || UNKNOWN,
        osName,
        osId,
    };
}
