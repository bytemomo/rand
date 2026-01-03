#include <windows.h>
#include <stdio.h>
#include <filesystem>
#include <iostream>

/*
 * protector.cpp
 *
 * This mimics a game executable or a secure launcher. Its job is to read
 * the payload from the disk and manually map it into memory.
 *
 * KEY TECHNIQUES:
 * - VirtualAlloc: Allocates memory manually.
 * - Manual Import Resolution: Links system DLLs manually.
 * - Base Relocations: Fixes memory addresses so the code runs at a random location.
 * - Stealth: It does NOT use LoadLibrary, keeping the module off the PEB list.
 */

namespace fs = std::filesystem;

PIMAGE_NT_HEADERS GetNtHeaders(LPVOID fileData) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)fileData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    return (PIMAGE_NT_HEADERS)((BYTE*)fileData + pDos->e_lfanew);
}

FARPROC GetProcAddressManual(BYTE* pBase, const char* funcName) {
    PIMAGE_NT_HEADERS pNt = GetNtHeaders(pBase);
    PIMAGE_EXPORT_DIRECTORY pExport =
        (PIMAGE_EXPORT_DIRECTORY)(pBase +
                                  pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pNames = (DWORD*)(pBase + pExport->AddressOfNames);
    DWORD* pFuncs = (DWORD*)(pBase + pExport->AddressOfFunctions);
    WORD* pOrds = (WORD*)(pBase + pExport->AddressOfNameOrdinals);

    printf("[?][Loader] Dumping dll exports\n");
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* szName = (char*)(pBase + pNames[i]);
        printf("[?][Loader] Found Export: %s \n", szName);
        if (strcmp(szName, funcName) == 0) {
            return (FARPROC)(pBase + pFuncs[pOrds[i]]);
        }
    }
    return NULL;
}

void* LoadAntiCheat(fs::path path) {
    printf("[+][Loader] Opening File: %s\n", path.string().c_str());

    HANDLE hFile = CreateFileA(path.string().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-][Loader] Failed to open file.\n");
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* pRawData = (BYTE*)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, pRawData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    PIMAGE_NT_HEADERS pNt = GetNtHeaders(pRawData);
    if (!pNt) return NULL;

    BYTE* pBase =
        (BYTE*)VirtualAlloc(NULL, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pBase) return NULL;

    {  // Copy Headers & Sections
        memcpy(pBase, pRawData, pNt->OptionalHeader.SizeOfHeaders);
        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            if (pSec[i].SizeOfRawData) {
                memcpy(pBase + pSec[i].VirtualAddress, pRawData + pSec[i].PointerToRawData, pSec[i].SizeOfRawData);
            }
        }
        free(pRawData);
    }

    {  // Base Relocations
        DWORD64 delta = (DWORD64)pBase - pNt->OptionalHeader.ImageBase;

        if (delta != 0 && pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            PIMAGE_BASE_RELOCATION pReloc =
                (PIMAGE_BASE_RELOCATION)(pBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                                     .VirtualAddress);

            while (pReloc->VirtualAddress) {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* list = (WORD*)(pReloc + 1);

                for (DWORD i = 0; i < count; i++) {
                    if (list[i] == 0) continue;

                    if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64 || (list[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD64* pPatch = (DWORD64*)(pBase + pReloc->VirtualAddress + (list[i] & 0xFFF));
                        *pPatch += delta;
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    {  // Resolve Imports
        if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
            PIMAGE_IMPORT_DESCRIPTOR pImport =
                (PIMAGE_IMPORT_DESCRIPTOR)(pBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                                                       .VirtualAddress);
            while (pImport->Name) {
                HMODULE hLib = LoadLibraryA((char*)(pBase + pImport->Name));
                PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pBase + pImport->OriginalFirstThunk);
                PIMAGE_THUNK_DATA pFunc = (PIMAGE_THUNK_DATA)(pBase + pImport->FirstThunk);
                if (!pThunk) pThunk = pFunc;

                while (pThunk->u1.AddressOfData) {
                    if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME pImName = (PIMAGE_IMPORT_BY_NAME)(pBase + pThunk->u1.AddressOfData);
                        pFunc->u1.Function = (DWORD64)GetProcAddress(hLib, pImName->Name);
                    }
                    pThunk++;
                    pFunc++;
                }
                pImport++;
            }
        }
    }

    {  // Execute DllMain
        typedef BOOL(WINAPI * DllMain_t)(HINSTANCE, DWORD, LPVOID);
        if (pNt->OptionalHeader.AddressOfEntryPoint) {
            DllMain_t pDllMain = (DllMain_t)(pBase + pNt->OptionalHeader.AddressOfEntryPoint);
            pDllMain((HINSTANCE)pBase, DLL_PROCESS_ATTACH, NULL);
        }
    }

    {  // Execute Protection
        typedef void (*RunProtection_t)();
        RunProtection_t runProtection = (RunProtection_t)GetProcAddressManual(pBase, "RunProtection");

        if (runProtection) {
            printf("[+][Loader] Found 'RunProtection' export. Executing...\n");
            runProtection();
        } else {
            printf("[-][Loader] Failed to find RunProtection export.\n");
        }
    }

    return pBase;
}

int main() {
    fs::path targetDll = "ac_payload.dll";
    void* addr = LoadAntiCheat(targetDll);
    if (!addr) {
        printf("[-][Loader] Failed to load Anti-Cheat.\n");
        return -1;
    }

    printf("[+][Loader] Loaded Anti-Cheat at: %p\n", addr);
    getchar();
    return 0;
}
