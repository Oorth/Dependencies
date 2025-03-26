//cl.exe /EHsc .\test.cpp /link /OUT:test.exe
#define DEBUG 1
#define DEBUG_FILE 0

#include <Windows.h>
#include <winternl.h>
#include "DbgMacros.h"

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

    fuk("Failed to find export address of: ", funcName, "\tGetlastError message -> ", GetLastError(), "\n");
    return nullptr;
}

void* SysFunction(const char* function_name, ...)
{
    void* vpfunction = nullptr;
    BYTE* pCleanSyscall = nullptr;
    DWORD dSyscall_SSN = 0;

    vpfunction = FindExportAddress(hNtdll, function_name);
    if(!vpfunction)
    {
        fuk("Couldn't find the function");
        return (void*)(~0ull);
    }

    BYTE* pBytes = reinterpret_cast<BYTE*>(vpfunction);
    if(pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1)
    {
        ok("Function ", function_name," is Unhooked");
        for(int i = 0; i < 32 ; ++i)
        {
            if(dSyscall_SSN != 0 && pCleanSyscall != nullptr) break;
            if(!dSyscall_SSN && i + 4 < 32 && pBytes[i] == 0xB8)
            {
                dSyscall_SSN = *(DWORD*)(pBytes + i + 1);
                norm("SSN:",CYAN" 0x", std::hex, dSyscall_SSN); 
            }

            if(!pCleanSyscall && i + 1 < 32 && (pBytes[i] == 0x0F || pBytes[i+1] == 0x05))
            {
                pCleanSyscall = pBytes + i;
                norm("Address of the Syscall: ", CYAN"0x", std::hex, reinterpret_cast<void*>(pCleanSyscall));
            }
        }

        if(dSyscall_SSN == 0 || pCleanSyscall == nullptr)
        {
            fuk("Couldn't find either the SSN or SYSCALL");
            return (void*)(~0ull);
        }
    }
    else
    {
        fuk("Function might be hooked");
        return (void*)(~0ull);
    }   

    BYTE syscall_code[] =
    {
        0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, SSN
        0x4C, 0x8B, 0xD1,               // mov r10, rcx
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // address placeholder
    };
    *(DWORD*)(syscall_code + 1) = dSyscall_SSN;
    *(UINT64*)(syscall_code + 14) = (UINT64)pCleanSyscall;

    void* exec_mem = VirtualAlloc(nullptr, sizeof(syscall_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem)
    {
        fuk("Failed to allocate executable memory");
        return (void*)(~0ull);
    }

    memcpy(exec_mem, syscall_code, sizeof(syscall_code));
    GenericSyscallType syscallFunc = reinterpret_cast<GenericSyscallType>(exec_mem);

    va_list args;
    va_start(args, function_name);

    void* argList[16] = {};
    for(int i = 1; i < 16 ; ++i)
    {
        void* arg = va_arg(args, void*);
        if(arg) argList[i] = arg;
    }
    va_end(args);

    void* retValue = nullptr;
    retValue = syscallFunc(argList[1], argList[2], argList[3], argList[4], argList[5],
                            argList[6], argList[7], argList[8], argList[9], argList[10],
                            argList[11], argList[12], argList[13], argList[14], argList[15]
    );

    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return retValue;
}

int main()
{
    const char* function_name;
    DWORD dSSN = 0;
    IO_STATUS_BLOCK ioStatusBlock = {};

    hNtdll = LoadLibraryW(L"ntdll.dll");
    if(!hNtdll)
    {
        fuk("cant load ntdll");
        return 1;
    } ok("loaded ntdll");

/////////////////////////////////////////////////////////////////////////////////////////////////////////
    norm(YELLOW"==============================================");

    char buffer[] = "!!!!Hello from NtWriteFile syscall!!!\n";
    ULONG length = sizeof(buffer) - 1;

    void* status = SysFunction("NtWriteFile", GetStdHandle(STD_OUTPUT_HANDLE), nullptr, nullptr, nullptr, &ioStatusBlock, buffer, length, nullptr, nullptr);

    if(status == (void*)(~0ull))
    {
        fuk("SysFunction failed");
        return 1;
    }

    if((NTSTATUS)uintptr_t(status) == 0) ok("NtWriteFile call successful!");
    else
    {
        fuk("NtWriteFile call failed!");
        //std::cout << "Status: 0x" << std::hex << status << std::endl;
    }

    norm(YELLOW"==============================================");
//////////////////////////////////////////////////////////////////////////////////////////////////////////

    HANDLE fileHandle = nullptr;
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objAttr;

    // Create full path with windows prefix
    WCHAR filePath[MAX_PATH] = L"\\??\\";
    WCHAR currentDir[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, currentDir);
    wcscat_s(filePath, MAX_PATH, currentDir);
    wcscat_s(filePath, MAX_PATH, L"\\testfile.txt");
    
    fileName.Buffer = filePath;
    fileName.Length = wcslen(filePath) * sizeof(WCHAR);
    fileName.MaximumLength = fileName.Length + sizeof(WCHAR);

    InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);


    void* status1 = SysFunction("NtCreateFile",
        &fileHandle, 
        FILE_GENERIC_WRITE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if(status == (void*)(~0ull))
    {
        fuk("SysFunction failed");
        return 1;
    }

    if((NTSTATUS)(uintptr_t(status1)) != 0)
    {
        fuk("Failed to create test file!\nStatus: ", std::hex, "0x", (NTSTATUS)(uintptr_t(status1)), "\n");
        return 1;
    }
    ok("File created successfully");

    norm(YELLOW"==============================================");
//////////////////////////////////////////////////////////////////////////////////////////////////////////

    norm("DONE :)");
    #if DEBUG_FILE
        details::close_log_file();
    #endif
    return 0;
}
