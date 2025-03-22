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
typedef void* (__stdcall *GenericSyscallType)(...);

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
    
    #if DEBUG
        std::cout << "Failed to find export address of: " << funcName << "\tGetlastError message -> " << GetLastError() << std::endl;
    #endif
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

void* SysFunction(DWORD dSSN, ...)
{
    BYTE syscall_code[] =
    {
        0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, SSN
        0x4C, 0x8B, 0xD1,               // mov r10, rcx
        0x0F, 0x05,                     // syscall
        0xC3                            // ret
    };
    *(DWORD*)(syscall_code + 1) = dSSN;

    void* exec_mem = VirtualAlloc(nullptr, sizeof(syscall_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem)
    {
        fuk("Failed to allocate executable memory");
        return nullptr;
    }

    memcpy(exec_mem, syscall_code, sizeof(syscall_code));

    GenericSyscallType syscallFunc = reinterpret_cast<GenericSyscallType>(exec_mem);

    // Process the variadic arguments.
    va_list args;
    va_start(args, dSSN);
    void* arg1 = va_arg(args, void*);
    void* arg2 = va_arg(args, void*);
    void* arg3 = va_arg(args, void*);
    void* arg4 = va_arg(args, void*);
    void* arg5 = va_arg(args, void*);
    void* arg6 = va_arg(args, void*);
    void* arg7 = va_arg(args, void*);
    void* arg8 = va_arg(args, void*);
    void* arg9 = va_arg(args, void*);
    va_end(args);


    void* retValue = syscallFunc(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return retValue;
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
    #if DEBUG
        std::cout << "SSN : " << dSSN << std::endl;
    #endif
/////////////////////////////////////////////////////////////////////////////////////////////////////////

    IO_STATUS_BLOCK ioStatusBlock = {};

    char buffer[] = "!!!!Hello from NtWriteFile syscall!!!\n\n";
    ULONG length = sizeof(buffer) - 1;

    void* status = SysFunction(dSSN, GetStdHandle(STD_OUTPUT_HANDLE), nullptr, nullptr, nullptr, &ioStatusBlock, buffer, length, nullptr, nullptr);

    if((NTSTATUS)(uintptr_t(status) == 0))
    {
        ok("NtWriteFile call successful!");
    }
    else
    {
        fuk("NtWriteFile call failed!");
        //std::cout << "Status: 0x" << std::hex << status << std::endl;
    }
//////////////////////////////////////////////////////////////////////////////////////////////////////////

   // Open a dummy handle (using CreateFile) to test NtClose
   HANDLE hFile = CreateFileW(L"testfile.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
   if (hFile == INVALID_HANDLE_VALUE)
   {
        fuk("Failed to create test file");
        return 1;
   }
   ok("File created successfully");

   dSSN = FindSyscallSSN("NtClose");
   if(!dSSN)
   {
       fuk("Coudnt find the ssn");
       return 1;
   }
   #if DEBUG
       std::cout << "SSN : " << dSSN << std::endl;
   #endif
   // Call NtClose using our syscall function
   status = SysFunction(dSSN, hFile);

   if((NTSTATUS)(uintptr_t(status) == 0))
   {
       ok("NtClose call successful!");
   }
   else
   {
       fuk("NtClose call failed!");
       std::cout << "Status: 0x" << std::hex << (NTSTATUS)(uintptr_t(status)) << std::endl;
   }

    return 0;
}
