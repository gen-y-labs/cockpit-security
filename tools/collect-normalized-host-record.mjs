#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import {
    collectHostSecurityRecord,
    deriveComplianceProfileFromPath,
    listOpenScapCandidatePaths,
    resolveHostDirReportPaths,
    writeNormalizedRecord,
} from "./host-security-normalizer.mjs";

function usage() {
    return [
        "Usage:",
        "  node tools/collect-normalized-host-record.mjs [options]",
        "",
        "Options:",
        "  --host-dir <path>         Directory containing per-source reports",
        "  --patch <path>            Patch report JSON file path",
        "  --trivy <path>            Trivy report JSON file path",
        "  --openscap <path>         OpenSCAP report JSON file path",
        "  --openscap-profile <id>   Filter OpenSCAP files by profile/source label",
        "  --metadata <path>         Optional metadata JSON with overrides/timings/versions",
        "  --scan-timestamp <iso>    Optional ISO8601 scan timestamp for unified record",
        "  --out <path>              Output normalized JSON file path",
        "  -h, --help                Show this help",
        "",
        "Notes:",
        "  - Use either --host-dir or explicit --patch/--trivy/--openscap paths.",
        "  - With --host-dir and multiple OpenSCAP files, the collector generates one record per OpenSCAP file.",
        "  - Missing reports are tolerated; all schema fields are still emitted with defaults.",
    ].join("\n");
}

function parseArgs(argv) {
    const parsed = {};

    for (let index = 0; index < argv.length; index += 1) {
        const arg = argv[index];

        if (arg === "-h" || arg === "--help") {
            parsed.help = true;
            continue;
        }

        if (!arg.startsWith("--"))
            throw new Error(`Unexpected argument: ${arg}`);

        const key = arg.slice(2);
        const value = argv[index + 1];
        if (!value || value.startsWith("--"))
            throw new Error(`Missing value for --${key}`);

        parsed[key] = value;
        index += 1;
    }

    return parsed;
}

function resolveOutputPath(args, multiRecordMode) {
    if (args.out)
        return path.resolve(args.out);
    if (args["host-dir"])
        return path.resolve(
            args["host-dir"],
            multiRecordMode ? "normalized-host-security-records.json" : "normalized-host-security-record.json"
        );

    return path.resolve(
        process.cwd(),
        multiRecordMode ? "normalized-host-security-records.json" : "normalized-host-security-record.json"
    );
}

function printWarnings(warnings) {
    if (warnings.length === 0)
        return;

    console.error(`Collector warnings (${warnings.length}):`);
    for (const warning of warnings)
        console.error(`- ${warning}`);
}

function printDefaultedFields(fields) {
    if (fields.length === 0) {
        console.log("Defaulted placeholder fields: none");
        return;
    }

    console.log(`Defaulted placeholder fields (${fields.length}):`);
    for (const field of fields)
        console.log(`- ${field}`);
}

function normalizeProfileLabel(value) {
    if (!value || typeof value !== "string")
        return "";

    return value.toLowerCase()
            .replace(/\.json$/i, "")
            .replace(/[^a-z0-9._-]+/g, "-")
            .replace(/^-+/, "")
            .replace(/-+$/, "");
}

function profileMatches(candidatePath, requestedProfile) {
    const candidateProfile = normalizeProfileLabel(deriveComplianceProfileFromPath(candidatePath));
    const requested = normalizeProfileLabel(requestedProfile);

    if (!candidateProfile || !requested)
        return false;

    return candidateProfile === requested ||
        candidateProfile.includes(requested) ||
        requested.includes(candidateProfile);
}

async function selectOpenScapPathFromHostDir(hostDir, requestedProfile) {
    const candidates = await listOpenScapCandidatePaths(hostDir);
    if (candidates.length === 0)
        return [null];

    if (requestedProfile) {
        const matches = candidates.filter(candidate => profileMatches(candidate, requestedProfile));
        if (matches.length === 0) {
            const candidateLabels = candidates
                    .map(candidate => `${path.basename(candidate)} (${deriveComplianceProfileFromPath(candidate)})`)
                    .join(", ");
            throw new Error(`No OpenSCAP report matched --openscap-profile '${requestedProfile}'. Candidates: ${candidateLabels}`);
        }

        return matches.sort((left, right) => left.localeCompare(right));
    }

    return candidates;
}

async function collectFromArgs(args) {
    let patchReportPath = args.patch ? path.resolve(args.patch) : null;
    let trivyReportPath = args.trivy ? path.resolve(args.trivy) : null;
    let openscapReportPaths = args.openscap ? [path.resolve(args.openscap)] : [null];
    const requestedOpenScapProfile = args["openscap-profile"] || null;

    if (args["host-dir"]) {
        const hostDir = path.resolve(args["host-dir"]);
        const resolved = await resolveHostDirReportPaths(hostDir);
        patchReportPath = patchReportPath || resolved.patchReportPath;
        trivyReportPath = trivyReportPath || resolved.trivyReportPath;
        if (!args.openscap)
            openscapReportPaths = await selectOpenScapPathFromHostDir(hostDir, requestedOpenScapProfile);
    }

    if (!args["host-dir"] && !args.openscap && requestedOpenScapProfile)
        throw new Error("--openscap-profile requires --host-dir unless --openscap is provided.");

    return {
        collections: await Promise.all(openscapReportPaths.map(async openscapReportPath => ({
            selectedOpenScapPath: openscapReportPath,
            result: await collectHostSecurityRecord({
                patchReportPath,
                trivyReportPath,
                openscapReportPath,
                metadataPath: args.metadata ? path.resolve(args.metadata) : null,
                scanTimestamp: args["scan-timestamp"] || null,
                selectedOpenScapProfile: requestedOpenScapProfile,
            }),
        }))),
    };
}

async function writeRecords(outputPath, collections) {
    if (collections.length === 1) {
        await writeNormalizedRecord(outputPath, collections[0].result.record);
        return;
    }

    const records = collections.map(collection => collection.result.record);
    await fs.writeFile(outputPath, `${JSON.stringify(records, null, 2)}\n`, "utf8");
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
        console.log(usage());
        return;
    }

    if (!args["host-dir"] && !args.patch && !args.trivy && !args.openscap)
        throw new Error("Provide --host-dir or at least one report path (--patch/--trivy/--openscap).");

    const collection = await collectFromArgs(args);
    const multiRecordMode = collection.collections.length > 1;
    const outputPath = resolveOutputPath(args, multiRecordMode);

    await writeRecords(outputPath, collection.collections);
    console.log(`Wrote normalized host record${multiRecordMode ? "s" : ""}: ${outputPath}`);

    for (const [index, item] of collection.collections.entries()) {
        if (item.selectedOpenScapPath) {
            console.log(`OpenSCAP source [${index + 1}]: ${item.selectedOpenScapPath} (profile: ${item.result.record.compliance_profile})`);
        }

        printWarnings(item.result.warnings);
        printDefaultedFields(item.result.defaultedFields);
    }
}

main().catch(error => {
    console.error(error instanceof Error ? error.message : String(error));
    console.error("");
    console.error(usage());
    process.exit(1);
});
