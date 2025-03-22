//cl.exe /EHsc .\test.cpp /link stub.obj /OUT:test.exe
#define DEBUG 1

#include <Windows.h>
#include <winternl.h>
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

    dSSN = FindSyscallSSN("NtWriteFile");
    if(!dSSN)
    {
        fuk("Coudnt find the ssn");
        return 1;
    }
    std::cout << "SSN : " << dSSN << std::endl;

    using NtWriteFile_t = NTSTATUS(NTAPI*)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,ULONG Length,PLARGE_INTEGER ByteOffset,PULONG Key);

    // Prepare arguments for NtWriteFile
    HANDLE fileHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE event = nullptr;
    PIO_APC_ROUTINE apcRoutine = nullptr;
    PVOID apcContext = nullptr;

    IO_STATUS_BLOCK ioStatusBlock;
    ioStatusBlock.Information = 0;
    ioStatusBlock.Status = 0;

    char buffer[] = "!!!!Hello from NtWriteFile syscall!!!\n\n";
    ULONG length = sizeof(buffer) - 1;
    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;
    PULONG key = nullptr;

    // Prepare syscall
    BYTE syscall_code[] =
    {
        0xB8, 0x00, 0x00, 0x00, 0x00,       // mov eax, SSN
        0x4C, 0x8B, 0xD1,                   // mov r10, rcx
        0x0F, 0x05,                         // syscall
        0xC3                                // ret
    };

    // Fill SSN
    *(DWORD*)(syscall_code + 1) = dSSN;


    // Execute syscall
    using SyscallType = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    
    // Allocate executable memory
    void* exec_mem = VirtualAlloc(nullptr, sizeof(syscall_code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!exec_mem)
    {
        fuk("Failed to allocate executable memory");
        return 1;
    }

    // Copy syscall code to executable memory
    memcpy(exec_mem, syscall_code, sizeof(syscall_code));

    SyscallType syscall_func = reinterpret_cast<SyscallType>(exec_mem);
    NTSTATUS status = syscall_func(fileHandle, event, apcRoutine, apcContext, &ioStatusBlock, buffer, length, &byteOffset, key);

    // Free the allocated memory
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    if (status == 0)
    {
        ok("NtWriteFile call successful!");
    } 
    else
    {
        fuk("NtWriteFile call failed!");
        std::cout << "Status: 0x" << std::hex << status << std::endl;
    }

    return 0;
}
