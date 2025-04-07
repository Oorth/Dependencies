//cl.exe /EHsc .\test.cpp /link /OUT:test.exe
/*

    Done with making dynamically obsfuscated stub for 
            SSN command (Integration pending)
            to do -> for other 2 commands 
            [mov needs changing]
            [did not start jump]
*/

#define LEAN_AND_MEAN
#define DEBUG 1
#define DEBUG_FILE 0
#define DEBUG_VECTOR 0

#define MAX_SYSCALLS 30
#define SIZE_OF_SYSCALL_CODE 64

#if DEBUG
    #include <iomanip>
#endif

#include <Windows.h>
#include <winternl.h>
#include "DbgMacros.h"
////////////////////////////////////////////////////////////////////////////////

HMODULE hNtdll = nullptr;
typedef void* (__stdcall *GenericSyscallType)(...);

////////////////////////////////////////////////////////////////////////////////

struct Sys_stb
{
    const char* function_name;
    DWORD SSN;
    void* pStubAddress;
    BYTE* pCleanSyscall;
};

BYTE* pSyscallPool = nullptr;
Sys_stb syscallEntries[MAX_SYSCALLS];
size_t stubCount = 0, stubOffset = 0;

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

BYTE* GenerateSyscallStub(Sys_stb* sEntry)
{
    BYTE* syscall_code = new BYTE[64]();
    BYTE nop[] = {0x90};
    int offset = 0;

    //===============================================================================================

    //Add random Nops
    for(int i = 0; i < rand() % 3; i++)                // Add random NOPs
    {
        memcpy(syscall_code + offset, nop, sizeof(nop));                      
        ++offset;
    }

    ///////////////////////////////////////////////SSN///////////////////////////////////////////////

    switch(rand() % 3)
    {  
        case 0:                                                     // HIGH_LOW
        {   
            norm(RED"IN 0 [SSN]"); 

            DWORD ssn = sEntry->SSN;
            BYTE lowByte = (BYTE)(ssn & 0xFF);
            DWORD highBytes = (ssn & 0xFFFFFF00);

            BYTE temp_code[] = 
            {
                0x31, 0xC0,                                         // xor eax, eax
                0xB0, 0x00,                                         // mov al, SSN_LOW
                0x81, 0xC0, 0x00, 0x00, 0x00, 0x00                  // add eax, SSN_HIGH_SHIFTED
            };
            *(BYTE*)(temp_code + 3) = lowByte;
            *(DWORD*)(temp_code + 6) = highBytes;

            memcpy(syscall_code + offset, temp_code, sizeof(temp_code));           
            offset += sizeof(temp_code);

            break;
        }

        case 1:                                                     // ADD_RANDOM
        {
            norm(RED"IN 1 [SSN]");
            BYTE randNum = (BYTE)(rand() % 0x50);

            BYTE temp_code[] =
            {
                0xB8, 0x00, 0x00, 0x00, 0x00,                    // mov eax, X
                0x05, 0x00, 0x00, 0x00, 0x00                     // add eax, Y
            };
            *(DWORD*)(temp_code + 1) = randNum;
            *(DWORD*)(temp_code + 6) = sEntry->SSN - randNum;

            memcpy(syscall_code + offset, temp_code, sizeof(temp_code));           
            offset += sizeof(temp_code);
            
            break;
        }

        case 2:                                                     // PUSH_POP
        {   
            norm(RED"IN 2 [SSN]");
            BYTE temp_code[] =
            {
                0x9C,                                        // pushfq (save flags)
                
                0x31, 0xC0,                                   // xor eax, eax
                0x68, 0x00, 0x00, 0x00, 0x00,                   // push SSN
                0x58,                                           // pop rax (SSN -> rax)

                0x9D,                                        // popfq (restore flags)
            };
            *(DWORD*)(temp_code + 4) = sEntry->SSN;
            
            memcpy(syscall_code + offset, temp_code, sizeof(temp_code));           
            offset += sizeof(temp_code);

            break;
        }

        default:
        {   norm(RED"DEFAULT [SSN]");
            BYTE temp_code[] =
            {
                0xB8, 0x00, 0x00, 0x00, 0x00                 // mov eax, SSN
            };
            *(DWORD*)(temp_code + 1) = sEntry->SSN;

            memcpy(syscall_code + offset, temp_code, sizeof(temp_code));
            offset += sizeof(temp_code);
        
            break;
        }
    }

    //===============================================================================================
    //Add random Nops
    for(int i = 0; i < rand() % 3; i++)                // Add random NOPs
    {
        memcpy(syscall_code + offset, nop, sizeof(nop));                      
        ++offset;
    }

    ///////////////////////////////////////////////MOV/////////////////////////////////////////////// 

    //switch(rand() % 3)
    switch(0)
    {  
        case 0:                                                     // xor and mov
        {
            norm(RED"in 0 [move]");
            BYTE tempcode[] = 
            {
                0x4D, 0x31, 0xD2,                   // xor r10, r10
                0x49, 0x89, 0xCA                    // mov r10, rcx 
            };
            memcpy(syscall_code + offset, tempcode, sizeof(tempcode));
            offset += sizeof(tempcode);
        break;
        }

        default:                                                                             
        {   norm(RED"in DEFAULT [MOV]");                                                                             

            BYTE mov_r10_rcx[] =
            {
                0x4C, 0x8B, 0xD1                                    // mov r10, rcx
            };
            
            memcpy(syscall_code + offset, mov_r10_rcx, sizeof(mov_r10_rcx));
            offset += sizeof(mov_r10_rcx);
        
            break;
        }
    }

    //===============================================================================================
    //Add random Nops
    for(int i = 0; i < rand() % 3; i++)                // Add random NOPs
    {
        memcpy(syscall_code + offset, nop, sizeof(nop));                      
        ++offset;
    }

    ///////////////////////////////////////////////JMP/////////////////////////////////////////////// 

    switch(rand() % 2)
    {
        case 0:                                                     // push and xchg
        {   
            norm(RED"in 0 [jmp]\n");
            BYTE jmp_code[] =
            {
                0x50,                                                           // push rax
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, syscall_addr
                0x48, 0x87, 0x04, 0x24,                                         // xchg rax, [rsp]
                0xC3                                                            // ret
            };
            *(UINT64*)(jmp_code + 3) = (UINT64)sEntry->pCleanSyscall;
            
            memcpy(syscall_code + offset, jmp_code, sizeof(jmp_code));
            offset += sizeof(jmp_code);

            break;
        }

        case 1:                                                     // Push + ret technique [Works]
        {
            norm(RED"in 1 [jmp]\n");
            BYTE jmp_code[] =
            {
                0x50,                                                           // push rax
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, syscall_addr
                0x48, 0x87, 0x04, 0x24,                                         // xchg rax, [rsp]
                0xC3                                                            // ret
            };
            *(UINT64*)(jmp_code + 3) = (UINT64)sEntry->pCleanSyscall;
            
            memcpy(syscall_code + offset, jmp_code, sizeof(jmp_code));
            offset += sizeof(jmp_code);

            break;
        }
        
        default:                                                                             
        {   norm(RED"in DEFAULT [JMP]");                                                                             

            BYTE jmp_code[] =
            {
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                // jmp [rip+0]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00     // syscall address
            };
            *(UINT64*)(jmp_code + 6) = (UINT64)sEntry->pCleanSyscall;
            
            memcpy(syscall_code + offset, jmp_code, sizeof(jmp_code));
            offset += sizeof(jmp_code);

            break;
        }
    }

    //===============================================================================================

    //Add random Nops
    for(int i = 0; i < rand() % 3; i++)                // Add random NOPs
    {
        memcpy(syscall_code + offset, nop, sizeof(nop));                      
        ++offset;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////

    // #if DEBUG
    //     norm("\nSyscall Code Contents:");
    //     for(int i = 0; i < SIZE_OF_SYSCALL_CODE; i++)
    //     {
    //         if(i % 16 == 0) std::cout << YELLOW"\n" << std::hex << std::setw(4) << std::setfill('0') << i << CYAN": ";
    //         std::cout << std::hex << std::setw(2) << std::setfill('0') << CYAN"" << std::setw(2) << std::setfill('0') << (int)syscall_code[i] << " ";
    //     }
    //     std::cout << RESET"\n";
    // #endif


    warn("ENDING FUNCTION");
    return syscall_code;
}

void* AddStubToPool(Sys_stb* sEntry, size_t NumberOfElements)
{
    BYTE* stubAddress = nullptr;

    if(stubCount >= MAX_SYSCALLS)
    {
        fuk("Max number of syscalls reached in pool");
        return (void*)(~0ull);
    }

    for(size_t j = 0; j < NumberOfElements; ++j)
    {
        void* vpfunction = FindExportAddress(hNtdll, sEntry[j].function_name);
        if(!vpfunction)
        {
            fuk("Couldn't find the function");
            return (void*)(~0ull);
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////

        BYTE* pBytes = reinterpret_cast<BYTE*>(vpfunction);
        if(pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1)
        {
            ok("Function ", sEntry[j].function_name," is Unhooked");
            for(int i = 0; i < 32; i++)
            {
                if(sEntry[j].SSN != 0 && sEntry[j].pCleanSyscall != nullptr) break;
                if(!sEntry[j].SSN && i + 4 < 32 && pBytes[i] == 0xB8)
                {
                    sEntry[j].SSN = *(DWORD*)(pBytes + i + 1);
                    norm("SSN:",CYAN" 0x", std::hex, sEntry[j].SSN); 
                }

                if(!sEntry[j].pCleanSyscall && i + 1 < 32 && (pBytes[i] == 0x0F || pBytes[i+1] == 0x05))
                {
                    sEntry[j].pCleanSyscall = pBytes + i;
                    norm("Address of the Syscall: ", CYAN"0x", std::hex, reinterpret_cast<void*>(sEntry[j].pCleanSyscall));
                }
            }

            if(sEntry[j].SSN == 0 || sEntry[j].pCleanSyscall == nullptr)
            {
                fuk("Couldn't find either the SSN or SYSCALL");
                return (void*)(~0ull);
            }
        }
        else
        {
            fuk("Function ", sEntry[j].function_name, " might be hooked");
            return (void*)(~0ull);
        }

        ok("Done ", sEntry[j].function_name, "\n");
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////

        BYTE* syscall_code = GenerateSyscallStub(sEntry);

        if(stubOffset + SIZE_OF_SYSCALL_CODE > MAX_SYSCALLS * SIZE_OF_SYSCALL_CODE)
        {
            fuk("The Syscall Pool is full");
            return (void*)(~0ull);
        }

        stubAddress = pSyscallPool + stubOffset;
        for (size_t i = 0; i < SIZE_OF_SYSCALL_CODE; i++) stubAddress[i] = syscall_code[i];
        
        sEntry[j].pStubAddress = stubAddress;
        stubOffset += SIZE_OF_SYSCALL_CODE;
        ++stubCount;
    }

    // Ensure memory is executable
    DWORD oldProtect;
    if (!VirtualProtect(pSyscallPool, stubOffset, PAGE_EXECUTE_READ, &oldProtect))
    {
        fuk("Failed to set RX permissions for syscall stubs.");
        return (void*)(~0ull);
    } 
    ok("Memory is executable");

    return (void*)(1ull);
}

void* SysFunction(const char* function_name, ...)
{

    void* pExecMem = nullptr;

    for(int i = 0; i < stubCount; ++i)
    {
        if(strcmp(syscallEntries[i].function_name, function_name) == 0)
        {
            pExecMem = syscallEntries[i].pStubAddress;
            break;
        }
    }
    if (!pExecMem)
    {
        fuk("Syscall not found: ", function_name);
        return (void*)(~0ull);
    }


    GenericSyscallType syscallFunc = reinterpret_cast<GenericSyscallType>(pExecMem);

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

    return retValue;
}

int main()
{
    srand(static_cast<unsigned>(time(nullptr)));
    const char* function_name;
    DWORD dSSN = 0;
    IO_STATUS_BLOCK ioStatusBlock = {};

    hNtdll = LoadLibraryW(L"ntdll.dll");
    if(!hNtdll)
    {
        fuk("cant load ntdll"); 
        return 1;
    } ok("loaded ntdll");

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    pSyscallPool = (BYTE*)VirtualAlloc(nullptr, MAX_SYSCALLS * 0x16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    size_t numSyscalls = 0;
    // syscallEntries[numSyscalls++] = {"NtCreateFile", 0, nullptr, nullptr};
    syscallEntries[numSyscalls++] = {"NtWriteFile", 0, nullptr, nullptr};
    // syscallEntries[numSyscalls++] = {"NtWriteVirtualMemory", 0, nullptr, nullptr};
    
    AddStubToPool(syscallEntries, numSyscalls);

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    norm("==============================================");
    // for(int i = 0; i < numSyscalls; i++)
    // {
    //     norm("Function Name: ", GREEN"", syscallEntries[i].function_name);
    //     norm("SSN: 0x", std::hex, CYAN"",syscallEntries[i].SSN);
    //     norm("Stub Address: 0x", std::hex, CYAN"", syscallEntries[i].pStubAddress);
    //     norm("Clean Syscall Address: 0x", std::hex, CYAN"", (void*)syscallEntries[i].pCleanSyscall);
    //     norm("------------------------");
    // }

    #if DEBUG
        norm("\nSyscall Pool Contents:");
        for(int i = 0; i < SIZE_OF_SYSCALL_CODE; i++) // Assuming max size of syscall_code is 32 bytes
        {
            if(i % 16 == 0) std::cout << YELLOW"\n" << std::hex << std::setw(4) << std::setfill('0') << i << CYAN": ";
            std::cout << std::hex << std::setw(2) << std::setfill('0') << CYAN"" << std::setw(2) << std::setfill('0') << (int)pSyscallPool[i] << " ";
        }
        std::cout << RESET"\n";
    #endif

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
        return 1;
        //std::cout << "Status: 0x" << std::hex << status << std::endl;
    }

    norm(YELLOW"==============================================");
// // //////////////////////////////////////////////////////////////////////////////////////////////////////////

    // HANDLE fileHandle = nullptr;
    // UNICODE_STRING fileName;
    // OBJECT_ATTRIBUTES objAttr;

    // // Create full path with windows prefix
    // WCHAR filePath[MAX_PATH] = L"\\??\\";
    // WCHAR currentDir[MAX_PATH];
    // GetCurrentDirectoryW(MAX_PATH, currentDir);
    // wcscat_s(filePath, MAX_PATH, currentDir);
    // wcscat_s(filePath, MAX_PATH, L"\\testfile.txt");
    
    // fileName.Buffer = filePath;
    // fileName.Length = wcslen(filePath) * sizeof(WCHAR);
    // fileName.MaximumLength = fileName.Length + sizeof(WCHAR);

    // InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);


    // void* status1 = SysFunction("NtCreateFile",
    //     &fileHandle, 
    //     FILE_GENERIC_WRITE,
    //     &objAttr,
    //     &ioStatusBlock,
    //     NULL,
    //     FILE_ATTRIBUTE_NORMAL,
    //     FILE_SHARE_READ,
    //     FILE_OVERWRITE_IF,
    //     FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    //     NULL,
    //     0
    // );

    // if(status == (void*)(~0ull))
    // {
    //     fuk("SysFunction failed");
    //     return 1;
    // }

    // if((NTSTATUS)(uintptr_t(status1)) != 0)
    // {
    //     fuk("Failed to create test file!\nStatus: ", std::hex, "0x", (NTSTATUS)(uintptr_t(status1)), "\n");
    //     return 1;
    // }
    // ok("File created successfully");

    norm(YELLOW"==============================================");
//     //////////////////////////////////////////////////////////////////////////////////////////////////////////

    norm("DONE :)");
    #if DEBUG_FILE
        details::close_log_file();
    #endif
    return 0;
}
