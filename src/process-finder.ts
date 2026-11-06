/**
 * Process Finder – Detects Antigravity's language server / hub process,
 * extracts the CSRF token and discovers the API port.
 *
 * Supports three discovery strategies in priority order:
 *   1. New-style log discovery: reads *-Antigravity.log in
 *      window[N]/exthost/output_logging_[T]/ (Antigravity IDE v2+, agy hub)
 *   2. Legacy log discovery: reads ls-main.log (older Antigravity IDE v1)
 *   3. Active process table scanning as a last resort
 *
 * Antigravity IDE v2+ architecture:
 *   - Backend binary: ~/.gemini/bin/agy.exe  (instead of language_server_*.exe)
 *   - Launch args:    --hub --hub-port=PORT --csrf_token=TOKEN
 *   - Protocol:       plain HTTP (not HTTPS)
 *   - Log path:       <logsDir>/<session>/window[N]/exthost/output_logging_[T]/*-Antigravity.log
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as http from 'http';
import * as https from 'https';
import * as process from 'process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const execAsync = promisify(exec);

export interface ProcessInfo {
    port: number;
    csrfToken: string;
}

interface ParsedProcess {
    pid: number;
    extensionPort: number;
    csrfToken: string;
}

/**
 * Finds the running Antigravity language server / hub process, extracts
 * connection parameters, and discovers the correct API port.
 */
export async function findAntigravityProcess(workspacePath?: string): Promise<ProcessInfo | null> {
    // 1. Try new-style log discovery first (Antigravity IDE v2+ with agy hub)
    const newLogInfo = await findFromNewStyleLogs();
    if (newLogInfo) {
        const workingPort = await findWorkingPort([newLogInfo.port], newLogInfo.csrfToken);
        if (workingPort) {
            return { port: workingPort, csrfToken: newLogInfo.csrfToken };
        }
    }

    // 2. Try legacy log discovery (older Antigravity IDE with ls-main.log)
    const legacyLogInfo = await findFromLegacyLogs();
    if (legacyLogInfo) {
        const workingPort = await findWorkingPort([legacyLogInfo.port], legacyLogInfo.csrfToken);
        if (workingPort) {
            return { port: workingPort, csrfToken: legacyLogInfo.csrfToken };
        }
    }

    // 3. Fallback: process table scanning (tries both agy and old LS binary names)
    for (const processName of getProcessNames()) {
        try {
            const parsed = await findProcess(processName, workspacePath);
            if (!parsed) { continue; }

            const ports = await getListeningPorts(parsed.pid);
            if (ports.length === 0 && parsed.extensionPort > 0) {
                ports.push(parsed.extensionPort);
            }
            if (ports.length === 0) { continue; }

            const workingPort = await findWorkingPort(ports, parsed.csrfToken);
            if (!workingPort) { continue; }

            return { port: workingPort, csrfToken: parsed.csrfToken };
        } catch {
            continue;
        }
    }

    return null;
}

// ─── Log Directory Discovery ──────────────────────────────────────────

function getCandidateLogDirs(): string[] {
    const home = os.homedir();
    const platform = process.platform;
    const dirs: string[] = [];

    if (platform === 'win32') {
        const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
        dirs.push(path.join(appData, 'Antigravity IDE', 'logs'));
        dirs.push(path.join(home, '.gemini', 'antigravity-ide', 'logs'));
        const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
        dirs.push(path.join(localAppData, 'Programs', 'Antigravity IDE', 'logs'));
    } else if (platform === 'darwin') {
        dirs.push(path.join(home, 'Library', 'Application Support', 'Antigravity IDE', 'logs'));
        dirs.push(path.join(home, '.gemini', 'antigravity-ide', 'logs'));
    } else {
        const configDir = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
        dirs.push(path.join(configDir, 'Antigravity IDE', 'logs'));
        dirs.push(path.join(home, '.gemini', 'antigravity-ide', 'logs'));
    }

    return dirs.filter(d => fs.existsSync(d));
}

// ─── NEW-STYLE Log Discovery (Antigravity IDE v2+ / agy hub) ─────────
//
// Log path pattern:
//   <logsDir>/<session>/window*/exthost/output_logging_*/*-Antigravity.log
//
// Key log line:
//   [LAUNCH] Spawning .../agy.exe ... --hub-port=PORT ... --csrf_token=TOKEN
//   [LAUNCH] Server at http://127.0.0.1:PORT is READY after N attempt(s).

async function findFromNewStyleLogs(): Promise<ProcessInfo | null> {
    const candidateDirs = getCandidateLogDirs();
    if (candidateDirs.length === 0) { return null; }

    let newestMtime = 0;
    let bestResult: ProcessInfo | null = null;

    for (const logsDir of candidateDirs) {
        try {
            // Sort session dirs newest-first (lexicographic desc works since they're timestamps)
            const sessionDirs = fs.readdirSync(logsDir)
                .map(d => ({ name: d, full: path.join(logsDir, d) }))
                .filter(({ full }) => { try { return fs.statSync(full).isDirectory(); } catch { return false; } })
                .sort((a, b) => b.name.localeCompare(a.name));

            for (const session of sessionDirs) {
                // Walk window* subdirs
                let windowNames: string[];
                try {
                    windowNames = fs.readdirSync(session.full)
                        .filter(d => /^window\d+$/i.test(d));
                } catch { continue; }

                for (const windowName of windowNames) {
                    const exthostDir = path.join(session.full, windowName, 'exthost');
                    let outputDirNames: string[];
                    try {
                        outputDirNames = fs.readdirSync(exthostDir)
                            .filter(d => d.startsWith('output_logging_'));
                    } catch { continue; }

                    // Newest output_logging_* first
                    outputDirNames.sort((a, b) => b.localeCompare(a));

                    for (const outputDirName of outputDirNames) {
                        const outputDir = path.join(exthostDir, outputDirName);
                        let logFileNames: string[];
                        try {
                            // Match *-Antigravity.log but NOT *-Antigravity LS.log
                            logFileNames = fs.readdirSync(outputDir)
                                .filter(f => /Antigravity\.log$/i.test(f) && !/Antigravity\s+LS/i.test(f));
                        } catch { continue; }

                        for (const logFileName of logFileNames) {
                            const logFile = path.join(outputDir, logFileName);
                            try {
                                const stat = fs.statSync(logFile);
                                if (stat.mtimeMs <= newestMtime) { continue; }

                                const result = parseNewStyleLog(logFile);
                                if (result) {
                                    newestMtime = stat.mtimeMs;
                                    bestResult = result;
                                }
                            } catch { continue; }
                        }
                    }
                }
            }
        } catch { continue; }
    }

    return bestResult;
}

function parseNewStyleLog(filePath: string): ProcessInfo | null {
    try {
        // Read enough to capture the LAUNCH lines (they appear near the start)
        const maxBytes = 32 * 1024;
        const fd = fs.openSync(filePath, 'r');
        const buffer = Buffer.alloc(maxBytes);
        let bytesRead = 0;
        try {
            bytesRead = fs.readSync(fd, buffer, 0, maxBytes, 0);
        } finally {
            try { fs.closeSync(fd); } catch { /* ignore */ }
        }
        const content = buffer.toString('utf8', 0, bytesRead);

        // Match: [LAUNCH] Spawning ... --hub-port=PORT ... --csrf_token=TOKEN
        const portMatch = content.match(/\[LAUNCH\].*?--hub-port[=\s]+(\d+)/i);
        const csrfMatch = content.match(/\[LAUNCH\].*?--csrf_token[=\s]+([a-f0-9-]{32,})/i);

        // Only trust it if the server confirmed READY (it's actually running)
        const isReady = /\[LAUNCH\]\s+Server at .* is READY/i.test(content);

        if (portMatch && csrfMatch && isReady) {
            return {
                port: parseInt(portMatch[1], 10),
                csrfToken: csrfMatch[1],
            };
        }
    } catch { /* ignore */ }
    return null;
}

// ─── LEGACY Log Discovery (Antigravity IDE v1 / ls-main.log) ─────────

async function findFromLegacyLogs(): Promise<ProcessInfo | null> {
    const candidateDirs = getCandidateLogDirs();
    if (candidateDirs.length === 0) {
        return null;
    }

    let newestFile: string | null = null;
    let newestMtime = 0;

    for (const logsDir of candidateDirs) {
        try {
            const subdirs = fs.readdirSync(logsDir);
            for (const d of subdirs) {
                const candidate = path.join(logsDir, d, 'ls-main.log');
                if (fs.existsSync(candidate)) {
                    const stat = fs.statSync(candidate);
                    if (stat.mtimeMs > newestMtime) {
                        newestMtime = stat.mtimeMs;
                        newestFile = candidate;
                    }
                }
            }
        } catch {
            continue;
        }
    }

    if (!newestFile) {
        return null;
    }

    try {
        let fd: number | null = null;
        const maxBytes = 64 * 1024;
        let content = '';
        try {
            fd = fs.openSync(newestFile, 'r');
            const buffer = Buffer.alloc(maxBytes);
            const bytesRead = fs.readSync(fd, buffer, 0, maxBytes, 0);
            content = buffer.toString('utf8', 0, bytesRead);
        } finally {
            if (fd !== null) {
                try { fs.closeSync(fd); } catch { /* ignore */ }
            }
        }

        const csrfMatch = content.match(/--csrf_token\s+([a-f0-9-]+)/i);
        const portMatch = content.match(/LS started on port\s+(\d+)/i) ||
                          content.match(/listening on random port at\s+(\d+)\s+for HTTPS/i);

        if (csrfMatch && portMatch) {
            return {
                csrfToken: csrfMatch[1],
                port: parseInt(portMatch[1], 10),
            };
        }
    } catch {
        return null;
    }

    return null;
}

// ─── Process Scanner ─────────────────────────────────────────────────

/**
 * Returns candidate process names to scan.
 * New Antigravity IDE v2 uses agy.exe as the hub server.
 * Old Antigravity IDE v1 used language_server_*.exe.
 */
function getProcessNames(): string[] {
    if (process.platform === 'win32') {
        return ['agy.exe', 'language_server_windows_x64.exe'];
    }
    if (process.platform === 'darwin') {
        const arch = process.arch === 'arm64' ? '_arm' : '';
        return ['agy', `language_server_macos${arch}`];
    }
    const arch = process.arch === 'arm64' ? '_arm' : '_x64';
    return ['agy', `language_server_linux${arch}`];
}

async function findProcess(name: string, workspacePath?: string): Promise<ParsedProcess | null> {
    if (process.platform === 'win32') {
        // Safe base64 encoded command to avoid cmd.exe quote stripping
        const psScript = `Get-CimInstance Win32_Process -Filter "name='${name}'" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress`;
        const b64 = Buffer.from(psScript, 'utf16le').toString('base64');
        const cmd = `powershell -NoProfile -NonInteractive -EncodedCommand ${b64}`;
        const { stdout } = await execAsync(cmd);
        return parseWindowsProcess(stdout);
    }

    const cmd = process.platform === 'darwin'
        ? `pgrep -fl ${name}`
        : `pgrep -af ${name}`;

    const { stdout } = await execAsync(cmd);
    return parseUnix(stdout, workspacePath);
}

function parseWindowsProcess(stdout: string): ParsedProcess | null {
    try {
        let data = JSON.parse(stdout.trim());
        if (Array.isArray(data)) {
            // Filter to Antigravity/hub processes only
            const filtered = data.filter((d: any) => {
                const cmdLine = (d.CommandLine || '');
                return /--app_data_dir[=\s]+antigravity/i.test(cmdLine)
                    || /--hub/i.test(cmdLine)
                    || cmdLine.toLowerCase().includes('antigravity')
                    || cmdLine.toLowerCase().includes('language_server');
            });
            if (filtered.length === 0) { return null; }
            data = filtered;
        } else {
            data = [data];
        }

        for (const item of data) {
            const cmdLine = item.CommandLine || '';
            const pid = item.ProcessId;
            if (!pid) { continue; }

            // New-style hub: --hub-port=PORT
            const hubPort = cmdLine.match(/--hub-port[=\s]+(\d+)/);
            // Old-style LS: --extension_server_port PORT
            const extPort = cmdLine.match(/--extension_server_port[=\s]+(\d+)/);
            const token = cmdLine.match(/--csrf_token[=\s]+([a-f0-9\-]+)/i);
            if (!token?.[1]) { continue; }

            const portMatch = hubPort || extPort;
            return {
                pid,
                extensionPort: portMatch ? parseInt(portMatch[1], 10) : 0,
                csrfToken: token[1],
            };
        }
        return null;
    } catch {
        return null;
    }
}

/**
 * Converts a workspace folder path to the workspace_id format
 * used by the language server's --workspace_id argument.
 */
function toWorkspaceId(folderPath: string): string {
    return 'file' + folderPath.replace(/ /g, '_20').replace(/\//g, '_');
}

function parseUnix(stdout: string, workspacePath?: string): ParsedProcess | null {
    const wsId = workspacePath ? toWorkspaceId(workspacePath) : null;
    // Match both new hub style (--hub-port) and old LS style (--extension_server_port)
    const lines = stdout.split('\n').filter(l =>
        l.includes('--hub-port') || l.includes('--extension_server_port')
    );

    // Prefer the line matching our workspace, fall back to first match
    const target = (wsId && lines.find(l => l.includes(wsId))) || lines[0];
    if (!target) { return null; }

    const parts = target.trim().split(/\s+/);
    const pid = parseInt(parts[0], 10);
    const cmd = target.substring(parts[0].length).trim();

    const hubPort = cmd.match(/--hub-port[=\s]+(\d+)/);
    const extPort = cmd.match(/--extension_server_port[=\s]+(\d+)/);
    const token = cmd.match(/--csrf_token[=\s]+([a-zA-Z0-9\-]+)/);
    const portMatch = hubPort || extPort;

    return {
        pid,
        extensionPort: portMatch ? parseInt(portMatch[1], 10) : 0,
        csrfToken: token ? token[1] : '',
    };
}

async function getListeningPorts(pid: number): Promise<number[]> {
    try {
        if (process.platform === 'win32') {
            const psScript = `Get-NetTCPConnection -OwningProcess ${pid} -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort | ConvertTo-Json -Compress`;
            const b64 = Buffer.from(psScript, 'utf16le').toString('base64');
            const cmd = `powershell -NoProfile -NonInteractive -EncodedCommand ${b64}`;
            const { stdout } = await execAsync(cmd);
            return parsePortOutput(stdout, pid);
        }

        const cmd = process.platform === 'darwin'
            ? `lsof -nP -a -iTCP -sTCP:LISTEN -p ${pid}`
            : `ss -tlnp 2>/dev/null | grep "pid=${pid}" || lsof -nP -a -iTCP -sTCP:LISTEN -p ${pid} 2>/dev/null`;

        const { stdout } = await execAsync(cmd);
        return parsePortOutput(stdout, pid);
    } catch {
        return [];
    }
}

function parsePortOutput(stdout: string, pid: number): number[] {
    const ports: number[] = [];

    if (process.platform === 'win32') {
        try {
            const trimmed = stdout.trim();
            if (!trimmed) { return []; }
            const data = JSON.parse(trimmed);
            const arr = Array.isArray(data) ? data : [data];
            for (const p of arr) {
                if (typeof p === 'number' && !ports.includes(p)) { ports.push(p); }
            }
        } catch { /* ignore */ }
        return ports.sort((a, b) => a - b);
    }

    // macOS / Linux – parse lsof output
    const lsofRegex = new RegExp(
        `^\\S+\\s+${pid}\\s+.*?(?:TCP|UDP)\\s+(?:\\*|[\\d.]+|\\[[\\da-f:]+\\]):(\\d+)\\s+\\(LISTEN\\)`,
        'gim'
    );
    let match;
    while ((match = lsofRegex.exec(stdout)) !== null) {
        const p = parseInt(match[1], 10);
        if (!ports.includes(p)) { ports.push(p); }
    }

    // Linux – parse ss output
    for (const line of stdout.split('\n')) {
        if (!line.includes(`pid=${pid}`)) { continue; }
        const cols = line.trim().split(/\s+/);
        const localAddr = cols[3];
        if (!localAddr) { continue; }
        const portMatch = localAddr.match(/:(\d+)$/);
        if (portMatch) {
            const p = parseInt(portMatch[1], 10);
            if (!ports.includes(p)) { ports.push(p); }
        }
    }

    return ports.sort((a, b) => a - b);
}

async function findWorkingPort(ports: number[], csrfToken: string): Promise<number | null> {
    for (const port of ports) {
        const ok = await testPort(port, csrfToken);
        if (ok) { return port; }
    }
    return null;
}

/**
 * Try HTTP first (new agy hub uses plain HTTP), then HTTPS (old language_server used HTTPS).
 */
async function testPort(port: number, csrfToken: string): Promise<boolean> {
    const okHttp = await testPortWithProtocol(port, csrfToken, 'http');
    if (okHttp) { return true; }
    return testPortWithProtocol(port, csrfToken, 'https');
}

function testPortWithProtocol(port: number, csrfToken: string, protocol: 'http' | 'https'): Promise<boolean> {
    return new Promise(resolve => {
        const lib = protocol === 'https' ? https : http;
        const req = lib.request(
            {
                hostname: '127.0.0.1',
                port,
                path: '/exa.language_server_pb.LanguageServerService/GetUnleashData',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Codeium-Csrf-Token': csrfToken,
                    'Connect-Protocol-Version': '1',
                },
                rejectUnauthorized: false,
                timeout: 3000,
            },
            res => {
                let body = '';
                res.on('data', (chunk: Buffer) => (body += chunk));
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try { JSON.parse(body); resolve(true); } catch { resolve(false); }
                    } else { resolve(false); }
                });
            }
        );
        req.on('error', () => resolve(false));
        req.on('timeout', () => { req.destroy(); resolve(false); });
        req.write(JSON.stringify({ wrapper_data: {} }));
        req.end();
    });
}
