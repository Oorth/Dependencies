//cl.exe /EHsc .\test.cpp /link /OUT:test.exe
#define DEBUG 1

#include <Windows.h>
#if DEBUG
    #include <iostream>
#endif
////////////////////////////////////////////////////////////////////////////////
#if DEBUG
    #define ok(something) std::cout << " [+] " << something << std::endl;
    #define fuk(something) std::cout << " [-] " << something << std::endl;
    #define warn(something) std::cout << " [!] " << something << std::endl;
#else
    #define ok(something)
    #define fuk(something)
    #define warn(something)
#endif
////////////////////////////////////////////////////////////////////////////////

HMODULE hNtdll = nullptr;

////////////////////////////////////////////////////////////////////////////////

void* FindExportAddress(HMODULE hModule, const char* funcName)
{
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* nameRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* ordRVAs = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
    {
        char* funcNameFromExport = (char*)((BYTE*)hModule + nameRVAs[i]);
        if (strcmp(funcNameFromExport, funcName) == 0)
        {
            DWORD funcRVA = funcRVAs[ordRVAs[i]];
            return (void*)((BYTE*)hModule + funcRVA);
        }
    }
    
    std::cout << "Failed to find export address of: " << funcName << "\tGetlastError message -> " << GetLastError() << std::endl;
    return nullptr;
}

DWORD FindSyscallSSN(const char* function_name)
{
    void* vpfunction = nullptr;
    DWORD dSyscall_SSN = 0;

    vpfunction = FindExportAddress(hNtdll, function_name);
    if(!vpfunction)
    {
        fuk("Coudnt find the function");
        return 0;
    }

    BYTE* pBytes = reinterpret_cast<BYTE*>(vpfunction);
    if(pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1)
    {
        ok("Function is Unhooked");
        dSyscall_SSN = *(DWORD*)(pBytes + 4);

        return dSyscall_SSN;
    }
    warn("Function might be hooked");

    return 0;
}

int main()
{
    const char* function_name;
    DWORD dSSN = 0;

    hNtdll = LoadLibraryW(L"ntdll.dll");
    if(!hNtdll)
    {
        fuk("cant load ntdll");
        return 1;
    } ok("loaded ntdll");

    dSSN = FindSyscallSSN("NtProtectVirtualMemory");
    if(!dSSN)
    {
        fuk("Coudnt find the ssn");
        return 1;
    }
    std::cout << "SSN : " << dSSN << std::endl;
    return 0;
}