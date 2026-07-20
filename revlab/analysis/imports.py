"""
Imports Analysis & Suspicious API Categorization Module
"""
from typing import Dict, List, Tuple
from ..parsers.common import BinaryObject, ImportSymbol

SUSPICIOUS_APIS: Dict[str, Tuple[str, str]] = {
    # Process Injection
    "VirtualAllocEx": ("Process Injection", "Allocates memory in remote process"),
    "WriteProcessMemory": ("Process Injection", "Writes payload into remote process memory"),
    "CreateRemoteThread": ("Process Injection", "Executes remote thread in target process"),
    "NtCreateThreadEx": ("Process Injection", "Native API to create remote thread"),
    "QueueUserAPC": ("Process Injection", "Asynchronous Procedure Call injection"),
    "SetThreadContext": ("Process Injection", "Modifies thread execution state"),

    # Anti-Debugging & Evasion
    "IsDebuggerPresent": ("Anti-Debug", "Queries PEB debug flag"),
    "CheckRemoteDebuggerPresent": ("Anti-Debug", "Checks process debug status"),
    "NtQueryInformationProcess": ("Anti-Debug", "Queries ProcessDebugPort or ProcessDebugFlags"),
    "OutputDebugStringA": ("Anti-Debug", "Generates debug message output"),
    "GetTickCount": ("Anti-Debug / Timing", "Measures execution delay"),
    "QueryPerformanceCounter": ("Anti-Debug / Timing", "High resolution timer for sandbox detection"),

    # Memory Manipulation & Execution
    "VirtualAlloc": ("Memory Allocation", "Allocates executable memory space"),
    "VirtualProtect": ("Memory Protection", "Changes memory permissions to Executable (RWX)"),
    "HeapCreate": ("Memory Allocation", "Creates heap memory"),

    # Keylogging & Hooks
    "SetWindowsHookExA": ("Hooking / Keylogger", "Installs global keyboard/mouse hook"),
    "SetWindowsHookExW": ("Hooking / Keylogger", "Installs global keyboard/mouse hook"),
    "GetAsyncKeyState": ("Keylogger", "Queries current keystroke state"),

    # Network & Communication
    "InternetOpenA": ("Network Communication", "Initializes WinINet HTTP connection"),
    "InternetOpenUrlA": ("Network Communication", "Connects to remote URL"),
    "HttpSendRequestA": ("Network Communication", "Sends HTTP payload"),
    "WSAStartup": ("Network Socket", "Initializes Windows Socket library"),
    "connect": ("Network Socket", "Establishes TCP socket connection"),
    "URLDownloadToFileA": ("Downloader", "Downloads file from URL to disk"),

    # Crypto & Encoding
    "CryptEncrypt": ("Cryptography", "Encrypts data block"),
    "CryptDecrypt": ("Cryptography", "Decrypts data block"),
    "CryptAcquireContextA": ("Cryptography", "Acquires Cryptographic Service Provider handle"),

    # Execution & Persistence
    "ShellExecuteA": ("Process Execution", "Launches executable command"),
    "CreateProcessA": ("Process Execution", "Creates new process"),
    "WinExec": ("Process Execution", "Executes command shell"),
    "RegSetValueExA": ("Persistence", "Modifies Registry autorun key"),
    "CreateServiceA": ("Persistence", "Installs system Windows service"),
}

def analyze_imports(binary: BinaryObject) -> Dict[str, any]:
    """Categorizes imported symbols and flags suspicious APIs."""
    suspicious_count = 0
    categories: Dict[str, List[ImportSymbol]] = {}

    for imp in binary.imports:
        func = imp.function_name
        if func in SUSPICIOUS_APIS:
            cat, desc = SUSPICIOUS_APIS[func]
            imp.is_suspicious = True
            imp.category = cat
            suspicious_count += 1
            
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(imp)
        else:
            imp.is_suspicious = False
            imp.category = "General"

    return {
        "total_imports": len(binary.imports),
        "suspicious_count": suspicious_count,
        "categories": categories,
        "imports": binary.imports
    }
