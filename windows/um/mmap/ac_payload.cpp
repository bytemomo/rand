#include <stdio.h>
#include <synchapi.h>
#include <windows.h>
#include <winnt.h>

/*
 * ac_payload.cpp
 * -------------------------------------------
 *
 * This is a simple DLL that represents our Anti-Cheat logic.
 * It is designed to be loaded manually. It exports a function
 * "RunProtection" that prints a message, proving code execution works
 * even when the DLL is not formally loaded by the OS.
 *
 */

void SafePrint(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    fflush(stdout);
}

void PerformIntegrityCheck() {
    SafePrint("[+][AC] Security Module Loaded\n");
    SafePrint("[+][AC] Base Address: %p\n", GetModuleHandle(NULL));

    while (true) {
        Sleep(1000);
        if (IsDebuggerPresent()) {
            SafePrint("[!][AC] User-Mode Debugger Detected !!\n");
            continue;
        }
        SafePrint("[+][AC] No Debugger attached.\n");
    }
}

extern "C" {
__declspec(dllexport) void RunProtection() { PerformIntegrityCheck(); }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) { return TRUE; }
