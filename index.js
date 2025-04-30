const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const fileType = require('file-type');

// patterns to detect cheats and suspicious files
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
    { name: "Malicious File Type", patterns: ["application/x-dosexec", "application/x-msdownload"] },
    { name: "Keylogger Detection", patterns: ["GetAsyncKeyState", "SetWindowsHookEx", "WH_KEYBOARD_LL"] },
    { name: "Remote Access Tool", patterns: ["TeamViewer", "AnyDesk", "RAT", "VNC", "RemoteDesktop"] },
    { name: "Packet Sniffer", patterns: ["WinPcap", "Npcap", "pcap_open_live", "pcap_loop"] },
    { name: "Process Hider", patterns: ["NtQuerySystemInformation", "ZwQuerySystemInformation", "HideProcess"] },
    { name: "Memory Editor", patterns: ["ReadProcessMemory", "WriteProcessMemory", "VirtualProtectEx"] },
    { name: "Kernel Exploit", patterns: ["NtLoadDriver", "ZwLoadDriver", "PsSetLoadImageNotifyRoutine"] },
    { name: "DirectX Hook", patterns: ["Direct3DCreate9", "D3D11CreateDevice", "IDXGISwapChain::Present"] },
    { name: "OpenGL Hook", patterns: ["wglSwapBuffers", "glDrawElements", "glDrawArrays"] },
    { name: "Vulkan Hook", patterns: ["vkCreateInstance", "vkCreateDevice", "vkQueuePresentKHR"] },
    { name: "Game Overlay", patterns: ["CreateDXGIFactory", "CreateDXGIFactory1", "CreateDXGIFactory2"] },
    { name: "Cheat Loader", patterns: ["LoadLibraryA", "LoadLibraryW", "GetProcAddress"] },
    { name: "Anti-Cheat Bypass", patterns: ["NtQueryInformationProcess", "ZwQueryInformationProcess", "ObRegisterCallbacks"] },
    { name: "DLL Injection", patterns: ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"] },
    { name: "Code Injection", patterns: ["SetThreadContext", "QueueUserAPC", "NtQueueApcThread"] },
    { name: "Shellcode Execution", patterns: ["VirtualAlloc", "CreateThread", "NtCreateThreadEx"] },
    { name: "Process Hollowing", patterns: ["NtUnmapViewOfSection", "ZwUnmapViewOfSection", "ResumeThread"] },
    { name: "Speedhack Detection", patterns: ["QueryPerformanceCounter", "timeGetTime", "GetTickCount"] },
    { name: "Silent Aim", patterns: ["silent_aim", "aim_smoothness", "aim_fov"] },
    { name: "Triggerbot Detection", patterns: ["triggerbot_enabled", "auto_shoot", "trigger_key"] },
    { name: "ESP Overlay", patterns: ["ESP", "entity_highlight", "player_box"] },
    { name: "Radar Hack", patterns: ["radar_enabled", "enemy_positions", "map_overlay"] },
    { name: "Teleport Hack", patterns: ["teleport_to", "player_coordinates", "set_position"] },
    { name: "Infinite Ammo", patterns: ["ammo_count", "no_reload", "unlimited_ammo"] },
    { name: "God Mode", patterns: ["invincibility", "no_damage", "infinite_health"] },
    { name: "Auto Loot", patterns: ["auto_pickup", "loot_radius", "item_grabber"] },
    { name: "Auto Heal", patterns: ["auto_heal", "health_regen", "instant_heal"] },
    { name: "Auto Farm", patterns: ["auto_farm", "resource_gathering", "auto_collect"] },
    { name: "Key Auth Loader", patterns: ["keyauth", "license_key", "auth_token"] },
    { name: "Cheat Config", patterns: ["config.json", "settings.ini", "cheat_config"] },
    { name: "Cheat Log", patterns: ["log.txt", "cheat_log", "debug_log"] },
    { name: "Cheat Cache", patterns: ["cache.dat", "temp_files", "cheat_cache"] },
    { name: "Cheat Backup", patterns: ["backup.zip", "cheat_backup", "config_backup"] },
    { name: "Cheat Framework", patterns: ["framework.dll", "cheat_framework", "hack_framework"] },
    { name: "Cheat Engine", patterns: ["Cheat Engine", "cheatengine-x86_64.exe", "cheatengine-i386.exe"] },
    { name: "Malware Loader", patterns: ["malware_loader", "payload.exe", "dropper"] },
    { name: "Backdoor Detection", patterns: ["reverse_shell", "bind_shell", "backdoor"] },
    { name: "Trojan Detection", patterns: ["trojan.exe", "malicious_payload", "remote_access"] },
    { name: "Exploit Detection", patterns: ["exploit.dll", "vulnerability", "privilege_escalation"] },
    { name: "Keylogger Detection", patterns: ["keylogger", "keystroke_logging", "keyboard_hook"] },
    { name: "Remote Access Tool", patterns: ["RAT", "remote_access", "teamviewer"] },
    { name: "Packet Sniffer", patterns: ["pcap", "packet_capture", "network_sniffer"] }
];

// directories to scan for cheats and suspicious files
const scanDirs = [
    path.join(os.homedir(), 'AppData', 'Roaming'),
    path.join(os.homedir(), 'AppData', 'Local'),
    path.join(os.homedir(), 'Documents'),
    path.join(os.homedir(), 'Downloads'),
    path.join(os.homedir(), 'Desktop'),
    path.join('C:', 'Program Files', 'FiveM'),
    path.join('C:', 'Program Files (x86)', 'FiveM')
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
        console.log(`[Error] Failed to scan file: ${filePath}. Error: ${error.message}`);
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
        console.log(`[Error] Failed to scan directory: ${dir}. Error: ${error.message}`);
    }
}

function performSystemChecks() {
    console.log('=== Performing System Checks ===');
    console.log(`Operating System: ${os.type()} ${os.release()}`);
    console.log(`CPU: ${os.cpus()[0].model}`);
    console.log(`Total Memory: ${(os.totalmem() / 1024 / 1024).toFixed(2)} MB`);
    console.log(`Free Memory: ${(os.freemem() / 1024 / 1024).toFixed(2)} MB`);
    console.log(`User: ${os.userInfo().username}`);
    console.log('=== System Checks Complete ===');
}

function displayDashboard() {
    console.clear();
    console.log('=== FiveM Cheat Scanner Dashboard ===');
    if (detectionSummary.length === 0) {
        console.log('No cheats or malicious files detected.');
    } else {
        console.log(`Detections Found: ${detectionSummary.length}`);
        detectionSummary.forEach((detection, index) => {
            console.log(`[${index + 1}] Type: ${detection.type}`);
            console.log(`    Rule: ${detection.rule}`);
            console.log(`    File: ${detection.file}`);
            if (detection.hash) {
                console.log(`    Hash: ${detection.hash}`);
            }
        });
    }
    console.log('=== Scan Complete ===');
}

function startScan() {
    console.clear();
    console.log('=== Starting FiveM Cheat Scanner ===');
    performSystemChecks();
    scanDirs.forEach(scanDirectory);
    displayDashboard();
}

startScan();