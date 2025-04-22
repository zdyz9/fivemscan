const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const chalk = require('chalk');
const fileType = require('file-type');

// patterns to detect cheats and suspicious files
// These patterns are examples and should be adjusted based on actual cheat signatures
// and file names. The patterns should be updated regularly to keep up with new cheats.
// The patterns are case-insensitive and can include partial matches.
// The detection rules are based on common cheat signatures and file names.
const suspiciousPatterns = [
    'HxCheats', 'RedENGINE', 'lynx', 'TiagoMenu', 'FalloutMenu', 'Eulen', 'Executor', 'CheatEngine',
    'dabinjector', 'modz', 'aimbot', 'triggerbot', 'wallhack', 'esp', 'silentaim', 'fov', 'noclip',
    'speedhack', 'bunnyhop', 'autoshot', 'aimassist', 'windows.storage.dll', 'ucrtbase.dll', 'msvcp_win.dll',
    'kernelbase.dll', 'advapi32.dll', 'sechost.dll', 'vcruntime140.dll', 'msvcp140.dll', 'kernel32.dll',
    'gdi32full.dll', 'gdi32.dll', 'user32.dll', 'oleaut32.dll', 'ole32.dll', 'd3d12.dll', 'd3d11.dll',
    'd3d10warp.dll', 'd3d10.dll', 'd3dx10_43.dll', 'd3dcompiler_43.dll', 'rpcrt4.dll', 'ntdll.dll', 'imm32.dll',
    'dxcore.dll', 'wldp.dll', 'kernel.appcore.dll', 'msedge.dll', 'wmiapsrv.dll', 'unsecapp.dll', 'wbemtest.dll',
    'winmgmt.dll', 'splwow32.dll', 'wmiadap.dll', 'wmiprvse.dll', 'wmic.dll', 'mofcomp.dll', 'chrome.dll', 'vlc.dll',
    'psreadline.dll', 'iexplore.dll', 'notepad.dll', 'usbdeview.dll', 'steamwebhelper.dll', 'fivem_steamchild.dll',
    'launcherpatcher.dll', 'perceptionsimulationservice.dll', 'mhyprot.sys', 'inpoutx64.sys', 'rockstarsteamhelper.dll',
    'fivem-premium.dll', 'clrloader.dll', 'Godmode', 'Aimbot', 'keyauth', 'KeyAuth', 'Snaplines', 'd3d11hook.cpp',
    'imgui.cpp', 'imgui_widgets.cpp', 'imgui_tables.cpp', 'imgui_draw.cpp', 'imstb_truetype.h', 'imgui_internal.h',
    'Save config', 'Fivem Bypass', 'Fivem Cheat', 'imgui_impl_dx11', 'imgui_impl_win32', 'imgui_impl_dx9', '@.themida',
    '@.winlice', 'Check if Invisible', 'Show Fov', 'Fov Color', 'Target NPC', 'Aim Settings', 'imgui', 'dxhook',
    'flyhack', 'collision_disabled', 'auto_aim', 'aim_assist', 'glowESP', 'drawThroughWalls', 'mouse_event',
    'SendInput', 'SetCursorPos'
];

// detection rules for various cheats and malicious files
// The detection rules are based on common cheat signatures and file names.
// The rules are case-insensitive and can include partial matches.
// The rules should be updated regularly to keep up with new cheats.
const detectionRules = [
    { name: "Skript Loader", patterns: ["D3D11CreateDeviceAndSwapChain", "AcquireSRWLockExclusive", "CreateFileW"] },
    { name: "TZX Loader", patterns: ["taskhostw.exe", "TZX.exe", "requestedExecutionLevel level='requireAdministrator'"] },
    { name: "Gosth Loader", patterns: ["api-ms-win-crt-locale-l1-1-0.dll", "api-ms-win-crt-runtime-l1-1-0.dll"] },
    { name: "HX Loader", patterns: ["tGDI32.dll", "requestedExecutionLevel level='asInvoker'"] },
    { name: "Wallhack Detection", patterns: ["glowESP", "wallhack_enabled", "drawThroughWalls"] },
    { name: "Mouse Movement Cheats", patterns: ["mouse_event", "SendInput", "SetCursorPos"] },
    { name: "Aimbot Detection", patterns: ["aimbot_target", "auto_aim", "aim_assist"] },
    { name: "Speedhack Detection", patterns: ["speed_multiplier", "game_speed", "time_scale"] },
    { name: "Noclip Detection", patterns: ["noclip_mode", "flyhack", "collision_disabled"] },
    { name: "ShellCode Injector", patterns: ["PPidSpoof", "ProcHollowing", "CreateProcess", "DynamicCodeInject", "PPIDDynCodeInject"] },
    { name: "CobaltStrike Malware", patterns: ["https://%hu.%hu.%hu.%hu:%u", "https://microsoft.com/telemetry/update.exe", "\\System32\\rundll32.exe"] },
    { name: "Escape Loader", patterns: ["ShellExecute", "@.mega0", "IsDebuggerPresent", "strtoll"] },
    { name: "HX Spoofer", patterns: ["Rich", "@.idata", "`.reloc", "@.themida", ".rsrc"] },
    { name: "Void Loader", patterns: ["@ALEX_ENG", ".boot", ".rsrc", "@.idata"] },
    { name: "Reversed Engine Loader", patterns: ["GetProcessWindowStation", "api-ms-win-crt-filesystem-l1-1-0.dll", "WTSSendMessageW"] },
    { name: "Evading Loader", patterns: ["@.mxrcy0", "h.mxrcy1", "GetModuleHandleA", "USER32.dll", "Normaliz.dll"] },
    { name: "Generic Cheat Hook", patterns: ["GetUserObjectInformationW", "CertFindCertificateInStore", "SHGetIconOverlayIndexA"] },
    { name: "DLL Injection", patterns: [".dll", "LoadLibrary", "GetProcAddress"] },
    { name: "Malicious File Type", patterns: ["application/x-dosexec", "application/x-msdownload"] }
];

// directories to scan for cheats and suspicious files
// The directories are common locations where cheats and malicious files may be found.
// The directories should be updated regularly to include new locations.
// The directories are case-insensitive and can include partial matches.
const scanDirs = [
    path.join(os.homedir(), 'AppData', 'Roaming'),
    path.join(os.homedir(), 'AppData', 'Local'),
    path.join(os.homedir(), 'Documents'),
    path.join(os.homedir(), 'Downloads'),
    path.join(os.homedir(), 'Desktop'),
    'C:\\Program Files\\FiveM',
    'C:\\Program Files (x86)\\FiveM'
];

let detectionSummary = [];

function calculateFileHash(filePath) {
    try {
        const fileBuffer = fs.readFileSync(filePath);
        const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        return hash;
    } catch {
        return null;
    }
}

function scanFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const fileHash = calculateFileHash(filePath);

        for (const rule of detectionRules) {
            for (const pattern of rule.patterns) {
                if (content.includes(pattern)) {
                    detectionSummary.push({
                        type: 'Rule Match',
                        rule: rule.name,
                        file: filePath,
                        hash: fileHash
                    });
                    return;
                }
            }
        }

        const fileTypeResult = fileType.fromFileSync(filePath);
        if (fileTypeResult && detectionRules.some(rule => rule.patterns.includes(fileTypeResult.mime))) {
            detectionSummary.push({
                type: 'Suspicious File',
                rule: 'Malicious File Type',
                file: filePath,
                hash: fileHash
            });
        }
    } catch (error) {
        console.log(chalk.red(`[Error] Failed to scan file: ${filePath}. Error: ${error.message}`));
    }
}

function scanDirectory(dir) {
    try {
        const files = fs.readdirSync(dir);
        for (const file of files) {
            const fullPath = path.join(dir, file);
            const stat = fs.statSync(fullPath);
            if (stat.isDirectory()) {
                scanDirectory(fullPath);
            } else {
                for (const pattern of suspiciousPatterns) {
                    if (file.toLowerCase().includes(pattern.toLowerCase())) {
                        detectionSummary.push({
                            type: 'File Name Match',
                            rule: pattern,
                            file: fullPath,
                            hash: calculateFileHash(fullPath)
                        });
                    }
                }
                scanFile(fullPath);
            }
        }
    } catch (error) {
        console.log(chalk.red(`[Error] Failed to scan directory: ${dir}. Error: ${error.message}`));
    }
}

function performSystemChecks() {
    console.log(chalk.bold.blue('=== Performing System Checks ==='));
    console.log(chalk.cyan(`Operating System: ${os.type()} ${os.release()}`));
    console.log(chalk.cyan(`CPU: ${os.cpus()[0].model}`));
    console.log(chalk.cyan(`Total Memory: ${(os.totalmem() / 1024 / 1024).toFixed(2)} MB`));
    console.log(chalk.cyan(`Free Memory: ${(os.freemem() / 1024 / 1024).toFixed(2)} MB`));
    console.log(chalk.cyan(`User: ${os.userInfo().username}`));
    console.log(chalk.bold.blue('=== System Checks Complete ==='));
}

function displayDashboard() {
    console.clear();
    console.log(chalk.bold.blue('=== FiveM Cheat Scanner Dashboard ==='));
    if (detectionSummary.length === 0) {
        console.log(chalk.green('No cheats or malicious files detected.'));
    } else {
        console.log(chalk.red(`Detections Found: ${detectionSummary.length}`));
        detectionSummary.forEach((detection, index) => {
            console.log(chalk.yellow(`[${index + 1}] Type: ${detection.type}`));
            console.log(chalk.cyan(`    Rule: ${detection.rule}`));
            console.log(chalk.magenta(`    File: ${detection.file}`));
            if (detection.hash) {
                console.log(chalk.gray(`    Hash: ${detection.hash}`));
            }
        });
    }
    console.log(chalk.bold.blue('=== Scan Complete ==='));
}

function startScan() {
    console.clear();
    console.log(chalk.bold.blue('=== Starting FiveM Cheat Scanner ==='));
    performSystemChecks();
    scanDirs.forEach(scanDirectory);
    displayDashboard();
}

startScan();