//cl.exe /EHsc .\test.cpp /link /OUT:test.exe
/*

    !NEED TO ADD A WAY TO GET A CLEAN NTDLL.DLL!

    Works

    size_t numSyscalls = 0;
    syscallEntries[numSyscalls++] = {"NtWriteFile", 0, 0, nullptr, nullptr};
    syscallEntries[numSyscalls++] = {"NtCreateFile", 0, 0, nullptr, nullptr};
    
    AddStubToPool(syscallEntries, numSyscalls);
    void* status = SysFunction("NtWriteFile", GetStdHandle(STD_OUTPUT_HANDLE), nullptr, nullptr, nullptr, &ioStatusBlock, buffer, length, nullptr, nullptr);

*/

#define LEAN_AND_MEAN
#define DEBUG 1
#define DEBUG_FILE 0
#define DEBUG_VECTOR 0

#define MAX_SYSCALLS 30
#define SIZE_OF_SYSCALL_CODE 64

//#include <Windows.h>
//h#include <winternl.h>
#include "ntghost.h"
#include "DbgMacros.h"
#include <ctime>
#if DEBUG | DEBUG_FILE
    #include <iomanip>
#endif

#define HEX_K 0xFF
#define X_C(c) static_cast<wchar_t>((c) ^ HEX_K)
////////////////////////////////////////////////////////////////////////////////

wchar_t obf_Usr_32[] = { X_C(L'u'), X_C(L's'), X_C(L'e'), X_C(L'r'), X_C(L'3'), X_C(L'2'), X_C(L'.'), X_C(L'd'), X_C(L'l'), X_C(L'l'), L'\0'};
wchar_t obf_Ker_32[] = { X_C(L'k'), X_C(L'e'), X_C(L'r'), X_C(L'n'), X_C(L'e'), X_C(L'l'), X_C(L'3'), X_C(L'2'), X_C(L'.'), X_C(L'd'), X_C(L'l'), X_C(L'l'), L'\0'};
wchar_t obf_Ntd_32[] = { X_C(L'n'), X_C(L't'), X_C(L'd'), X_C(L'l'), X_C(L'l'), X_C(L'.'), X_C(L'd'), X_C(L'l'), X_C(L'l'), L'\0'};

////////////////////////////////////////////////////////////////////////////////

typedef void* (__stdcall *GenericSyscallType)(...);
void* FindExportAddress(HMODULE, const char*);

//===============================================================================

typedef BOOL (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
// typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
// typedef DWORD (WINAPI *pGetCurrentDirectoryW)(DWORD, LPWSTR);
// typedef DWORD (WINAPI *pGetLastError)(VOID);

////////////////////////////////////////////////////////////////////////////////

struct Sys_stb
{
    const char* function_name;
    DWORD SSN;
    size_t stubsize;
    void* pStubAddress;
    BYTE* pCleanSyscall;
}syscallEntries[MAX_SYSCALLS];

struct _LIBS
{
    HMODULE hNtdll;
    HMODULE hKERNEL32;
    HMODULE hUsr32;
}sLibs;

typedef struct _MY_FUNCTIONS
{
    pVirtualProtect MyVirtualProtect;
}_MY_FUNCTIONS;
_MY_FUNCTIONS fn;

BYTE* pSyscallPool = nullptr;
size_t stubCount = 0, stubOffset = 0;
HMODULE hNtdll = nullptr;

////////////////////////////////////////////////////////////////////////////////

int GetFunctions()
{
    HMODULE kernel32Base = NULL;
    HMODULE ntdllBase = NULL;

    #ifdef _M_IX86
        PEB* pPEB = (PEB*) __readgsqword(0x30);
    #else
        PEB* pPEB = (PEB*) __readgsqword(0x60);   
    #endif
    norm("PEB ->", CYAN" 0x", std::hex, (void*)pPEB);
    

    PEB_LDR_DATA* pLdr = pPEB->Ldr;
    norm("\nLDR ->", CYAN" 0x", std::hex, (void*)pLdr);
    
    //=======================================================================

    for (int i = 0; obf_Usr_32[i] != '\0'; i++) obf_Usr_32[i] ^= HEX_K;
    for (int i = 0; obf_Ker_32[i] != '\0'; i++) obf_Ker_32[i] ^= HEX_K;
    for (int i = 0; obf_Ntd_32[i] != '\0'; i++) obf_Ntd_32[i] ^= HEX_K;
    
    LIST_ENTRY* head = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY* current = head->Flink;
    while (current != head)
    {
        LDR_DATA_TABLE_ENTRY* entry = ((LDR_DATA_TABLE_ENTRY*)((PCHAR)(current) - (ULONG_PTR)(&((LDR_DATA_TABLE_ENTRY*)0)->InMemoryOrderLinks)));
        
        if (entry->BaseDllName.Buffer != nullptr)
        {
            if (_wcsicmp(entry->BaseDllName.Buffer, obf_Ker_32) == 0) sLibs.hKERNEL32 = (HMODULE)entry->DllBase;
            else if (_wcsicmp(entry->BaseDllName.Buffer, obf_Ntd_32) == 0) sLibs.hNtdll = (HMODULE)entry->DllBase;
            else if (_wcsicmp(entry->BaseDllName.Buffer, obf_Usr_32) == 0) sLibs.hUsr32 = (HMODULE)entry->DllBase;
        }
        current = current->Flink;
    }

    for (size_t i = 0; i < wcslen(obf_Usr_32); i++) obf_Usr_32[i] = 0;
    for (size_t i = 0; i < wcslen(obf_Ker_32); i++) obf_Ker_32[i] = 0;
    for (size_t i = 0; i < wcslen(obf_Ntd_32); i++) obf_Ntd_32[i] = 0;

    if(sLibs.hKERNEL32 == 0 || sLibs.hNtdll == 0 || sLibs.hUsr32 == 0)
    {
        norm("\n");fuk("Problems with Dlls");
        return 0;
    }

    //=======================================================================
    norm(YELLOW"\n======================================================");
    norm("\nKernel32 Base: ", CYAN"0x", std::hex, sLibs.hKERNEL32);
    norm("\nNTDLL Base: ", CYAN"0x", std::hex, sLibs.hNtdll);
    norm("\nUsr32 Base: ", CYAN"0x", std::hex, sLibs.hUsr32);

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
norm("!!!!!!!!!!!!!!!!");
    fn.MyVirtualProtect = (pVirtualProtect)FindExportAddress(sLibs.hKERNEL32, "VirtualProtect");
norm("@@@@@@@@@@@@@@@@");
    if(!fn.MyVirtualProtect) fuk("No Virtual protek");
    ok("Got Virtual Protek");

    return 1;
}

BYTE* GenerateSyscallStub(Sys_stb* sEntry)
{
    BYTE* syscall_code = new BYTE[64]();
    BYTE nop[] = {0x90}, pushf[] = {0x9c}, popf[] = {0x9d};
    size_t Generate_Syscall_Offset = 0;
    
    // memcpy(syscall_code + Generate_Syscall_Offset, pushf, sizeof(pushf));
    // ++Generate_Syscall_Offset;
    //===============================================================================================

    //Add random Nops
    for(int i = 0; i < rand() % 3; ++i)                // Add random NOPs
    {
        memcpy(syscall_code + Generate_Syscall_Offset, nop, sizeof(nop));                      
        ++Generate_Syscall_Offset;
    }

    ///////////////////////////////////////////////SSN///////////////////////////////////////////////

    // switch(9)
    switch(rand() % 3)
    {  
        case 0:                                                     // HIGH_LOW
        {   
            norm(YELLOW"in 0 [SSN] "); 

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

            memcpy(syscall_code + Generate_Syscall_Offset, temp_code, sizeof(temp_code));           
            Generate_Syscall_Offset += sizeof(temp_code);

            break;
        }

        case 1:                                                     // ADD_RANDOM
        {
            norm(YELLOW"IN 1 [SSN] ");
            BYTE randNum = (BYTE)(rand() % 0x50);

            BYTE temp_code[] =
            {
                0xB8, 0x00, 0x00, 0x00, 0x00,                    // mov eax, X
                0x05, 0x00, 0x00, 0x00, 0x00                     // add eax, Y
            };
            *(DWORD*)(temp_code + 1) = randNum;
            *(DWORD*)(temp_code + 6) = sEntry->SSN - randNum;

            memcpy(syscall_code + Generate_Syscall_Offset, temp_code, sizeof(temp_code));           
            Generate_Syscall_Offset += sizeof(temp_code);
            
            break;
        }

        case 2:                                                     // PUSH_POP
        {   
            norm(YELLOW"IN 2 [SSN] ");
            BYTE temp_code[] =
            {
                0x9C,                                        // pushfq (save flags)
                
                0x31, 0xC0,                                   // xor eax, eax
                0x68, 0x00, 0x00, 0x00, 0x00,                   // push SSN
                0x58,                                           // pop rax (SSN -> rax)

                0x9D,                                        // popfq (restore flags)
            };
            *(DWORD*)(temp_code + 4) = sEntry->SSN;
            
            memcpy(syscall_code + Generate_Syscall_Offset, temp_code, sizeof(temp_code));           
            Generate_Syscall_Offset += sizeof(temp_code);

            break;
        }

        default:
        {   norm(YELLOW"DEFAULT [SSN] ");
            BYTE temp_code[] =
            {
                0xB8, 0x00, 0x00, 0x00, 0x00                 // mov eax, SSN
            };
            *(DWORD*)(temp_code + 1) = sEntry->SSN;

            memcpy(syscall_code + Generate_Syscall_Offset, temp_code, sizeof(temp_code));
            Generate_Syscall_Offset += sizeof(temp_code);
        
            break;
        }
    }

    //===============================================================================================
    //Add random Nops
    for(int i = 0; i < rand() % 3; ++i)                // Add random NOPs
    {
        memcpy(syscall_code + Generate_Syscall_Offset, nop, sizeof(nop));                      
        ++Generate_Syscall_Offset;
    }

    ///////////////////////////////////////////////MOV/////////////////////////////////////////////// 

    //switch(9)
    switch(rand() % 4)
    {  
        case 0:                                                     // xor and mov
        {
            norm(YELLOW"in 0 [move] ");
            BYTE tempcode[] = 
            {
                0x4D, 0x31, 0xD2,                   // xor r10, r10
                0x49, 0x89, 0xCA                    // mov r10, rcx 
            };
            memcpy(syscall_code + Generate_Syscall_Offset, tempcode, sizeof(tempcode));
            Generate_Syscall_Offset += sizeof(tempcode);
        break;
        }

        case 1:                                                     // and then move
        {
            norm(YELLOW"in 1 [move] ");

            BYTE tempcode[] = 
            {
                0x9c,                                       // pushf
                0x49, 0x81, 0xE2, 0x00, 0x00, 0x00, 0x00,   // and r10, 0
                0x49, 0x89, 0xCA,                           // mov r10, rcx
                0x9d                                        // popf
            };
            memcpy(syscall_code + Generate_Syscall_Offset, tempcode, sizeof(tempcode));
            Generate_Syscall_Offset += sizeof(tempcode);
        
            break;
        }

        case 2:                                                     // push move pop
        {   
            norm(YELLOW"in 2 [move] ");                                                                             
            BYTE tempcode[] = 
            {
                0x9c,                                       // pushf
                0x51,                                       // push rcx
                0x4C, 0x8B, 0x14, 0x24,                     // mov r10, [rsp]
                0x59,                                       // pop rcx
                0x9d                                        // popf
            };
            memcpy(syscall_code + Generate_Syscall_Offset, tempcode, sizeof(tempcode));
            Generate_Syscall_Offset += sizeof(tempcode);
        
            break;
        }

        case 3:                                                     // push xor xchg pop
        {
            norm(YELLOW"in 3 [move] ");
            BYTE tempcode[] = 
            {
                0x9c,                           // pushf
                0x51,                           // push rcx
                0x49, 0x31, 0xD2,               // xor r10, r10
                0x4C, 0x87, 0x14, 0x24,         // xchg r10, [rsp]
                0x59,                           // pop rcx
                0x9d                            // popf
            };
            memcpy(syscall_code + Generate_Syscall_Offset, tempcode, sizeof(tempcode));
            Generate_Syscall_Offset += sizeof(tempcode);
        break;
        }

        default:                                                                             
        {   norm(YELLOW"in DEFAULT [MOV] ");                                                                             

            BYTE mov_r10_rcx[] =
            {
                0x4C, 0x8B, 0xD1                                    // mov r10, rcx
            };
            
            memcpy(syscall_code + Generate_Syscall_Offset, mov_r10_rcx, sizeof(mov_r10_rcx));
            Generate_Syscall_Offset += sizeof(mov_r10_rcx);
        
            break;
        }
    }

    //===============================================================================================
    //Add random Nops
    for(int i = 0; i < rand() % 3; ++i)                // Add random NOPs
    {
        memcpy(syscall_code + Generate_Syscall_Offset, nop, sizeof(nop));                      
        ++Generate_Syscall_Offset;
    }

    ///////////////////////////////////////////////JMP/////////////////////////////////////////////// 

    //switch(9)
    switch(rand() % 3)
    {
        case 0:                                                     // push and xchg
        {   
            norm(YELLOW"in 0 [jmp] \n");
            BYTE jmp_code[] =
            {
                0x50,                                                           // push rax
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, syscall_addr
                0x48, 0x87, 0x04, 0x24,                                         // xchg rax, [rsp]
                0xC3                                                            // ret
            };
            *(UINT64*)(jmp_code + 3) = (UINT64)sEntry->pCleanSyscall;
            
            memcpy(syscall_code + Generate_Syscall_Offset, jmp_code, sizeof(jmp_code));
            Generate_Syscall_Offset += sizeof(jmp_code);

            break;
        }

        case 1:                                                     // Push + ret technique
        {
            norm(YELLOW"in 1 [jmp] \n");
            BYTE jmp_code[] =
            {
                0x50,                                                           // push rax
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, syscall_addr
                0x48, 0x87, 0x04, 0x24,                                         // xchg rax, [rsp]
                0xC3                                                            // ret
            };
            *(UINT64*)(jmp_code + 3) = (UINT64)sEntry->pCleanSyscall;
            
            memcpy(syscall_code + Generate_Syscall_Offset, jmp_code, sizeof(jmp_code));
            Generate_Syscall_Offset += sizeof(jmp_code);

            break;
        }
        
        case 2:                                                     // Using Upper and Lower bits
        {
            norm(YELLOW"in 2 [jmp] \n");
            BYTE jmp_code[] =
            {
                0x9C,                               // pushf
                0x48, 0xC7, 0x04, 0x24,             // mov dword [rsp], imm32 (lower half)
                0x00, 0x00, 0x00, 0x00,
                0xC7, 0x44, 0x24, 0x04,             // mov dword [rsp+4], imm32 (upper half)
                0x00, 0x00, 0x00, 0x00,
                //0x9D,                               // popf
                0xC3,                               // ret
            };
            
            *(DWORD*)(jmp_code + 5) = (DWORD)((UINT64)sEntry->pCleanSyscall & 0xFFFFFFFF);
            *(DWORD*)(jmp_code + 13) = (DWORD)((UINT64)sEntry->pCleanSyscall >> 32);

            memcpy(syscall_code + Generate_Syscall_Offset, jmp_code, sizeof(jmp_code));
            Generate_Syscall_Offset += sizeof(jmp_code);

            break;
        }

        default:                                                                             
        {   norm(YELLOW"in DEFAULT [JMP] ");                                                                             

            BYTE jmp_code[] =
            {
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                // jmp [rip+0]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00     // syscall address
            };
            *(UINT64*)(jmp_code + 6) = (UINT64)sEntry->pCleanSyscall;
            
            memcpy(syscall_code + Generate_Syscall_Offset, jmp_code, sizeof(jmp_code));
            Generate_Syscall_Offset += sizeof(jmp_code);

            break;
        }
    }

    //===============================================================================================

    //Add random Nops
    for(int i = 0; i < rand() % 3; ++i)                // Add random NOPs
    {
        memcpy(syscall_code + Generate_Syscall_Offset, nop, sizeof(nop));                      
        ++Generate_Syscall_Offset;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////

    // memcpy(syscall_code + Generate_Syscall_Offset, popf, sizeof(popf));
    // ++Generate_Syscall_Offset;

    sEntry->stubsize = Generate_Syscall_Offset;

    #if DEBUG
        norm("Syscall Code Contents:");
        for(int i = 0; i < SIZE_OF_SYSCALL_CODE; ++i)
        {
            if(i % 16 == 0) std::cout << YELLOW"\n" << std::hex << std::setw(4) << std::setfill('0') << i << CYAN": ";
            std::cout << std::hex << std::setw(2) << std::setfill('0') << CYAN"" << std::setw(2) << std::setfill('0') << (int)syscall_code[i] << " ";
        }
        std::cout << RESET"\n";
    #endif

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
            fuk("Couldn't find the function\n");
            return (void*)(~0ull);
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////

        BYTE* pBytes = reinterpret_cast<BYTE*>(vpfunction);
        if(pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1)
        {
            norm("\n");ok("Function ", sEntry[j].function_name," is Unhooked\n");
            for(int i = 0; i < 32; ++i)
            {
                if(sEntry[j].SSN != 0 && sEntry[j].pCleanSyscall != nullptr) break;
                if(!sEntry[j].SSN && i + 4 < 32 && pBytes[i] == 0xB8)
                {
                    sEntry[j].SSN = *(DWORD*)(pBytes + i + 1);
                    //norm("SSN:",CYAN" 0x", std::hex, sEntry[j].SSN, "\n"); 
                }

                if(!sEntry[j].pCleanSyscall && i + 1 < 32 && (pBytes[i] == 0x0F || pBytes[i+1] == 0x05))
                {
                    sEntry[j].pCleanSyscall = pBytes + i;
                    //norm("Address of the Syscall: ", CYAN"0x", std::hex, reinterpret_cast<void*>(sEntry[j].pCleanSyscall), "\n");
                }
            }

            if(sEntry[j].SSN == 0 || sEntry[j].pCleanSyscall == nullptr)
            {
                fuk("Couldn't find either the SSN or SYSCALL\n");
                return (void*)(~0ull);
            }
        }
        else
        {
            fuk("Function ", sEntry[j].function_name, " might be hooked\n");
            return (void*)(~0ull);
        }

        ok("Done ", sEntry[j].function_name, "\n");
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////

        BYTE* syscall_code = GenerateSyscallStub(&sEntry[j]);

        if(stubOffset + SIZE_OF_SYSCALL_CODE > MAX_SYSCALLS * SIZE_OF_SYSCALL_CODE)
        {
            fuk("The Syscall Pool is full");
            return (void*)(~0ull);
        }

        stubAddress = pSyscallPool + stubOffset;
        for (size_t i = 0; i < SIZE_OF_SYSCALL_CODE; ++i) stubAddress[i] = syscall_code[i];
        
        sEntry[j].pStubAddress = stubAddress;
        stubOffset += sEntry->stubsize;

        ++stubCount;
    }

    // Ensure memory is executable
    DWORD oldProtect;
    if (fn.MyVirtualProtect(pSyscallPool, stubOffset, 0x20, &oldProtect))
    {
        fuk("Failed to set RX permissions for syscall stubs.");
        return (void*)(~0ull);
    } 
    ok("Memory is executable\n");

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

// void InitUnicodeString(UNICODE_STRING& u, const wchar_t* s)
// {
//     size_t len = wcslen(s) * sizeof(wchar_t);
//     u.Length        = (USHORT)len;
//     u.MaximumLength = (USHORT)(len + sizeof(wchar_t));
//     u.Buffer        = const_cast<wchar_t*>(s);
// }

int main()
{
    srand(static_cast<unsigned>(time(nullptr)));
    const char* function_name;
    DWORD dSSN = 0;
    IO_STATUS_BLOCK ioStatusBlock = {};

    if(!GetFunctions())
    {
        return 1;
    }
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

//     pSyscallPool = (BYTE*)((pVirtualAlloc)sGhostFn.pVirtualAlloc)(nullptr, MAX_SYSCALLS * 0x40, 0x00001000 | 0x00002000, 0x40);
    
//     size_t numSyscalls = 0;
//     syscallEntries[numSyscalls++] = {"NtWriteFile", 0, 0, nullptr, nullptr};
//     syscallEntries[numSyscalls++] = {"NtCreateFile", 0, 0, nullptr, nullptr};
//     // syscallEntries[numSyscalls++] = {"NtWriteVirtualMemory", 0, nullptr, nullptr};
    
//     AddStubToPool(syscallEntries, numSyscalls);

//     ///////////////////////////////////////////////////////////////////////////////////////////////////////////

//     norm("==============================================\n");
//     for(int i = 0; i < numSyscalls; ++i)
//     {
//         norm("Function Name: ", GREEN"", syscallEntries[i].function_name);
//         norm("\nSSN: 0x", std::hex, CYAN"",syscallEntries[i].SSN);
//         norm("\nStub Address: 0x", std::hex, CYAN"", syscallEntries[i].pStubAddress);
//         norm("\nClean Syscall Address: 0x", std::hex, CYAN"", (void*)syscallEntries[i].pCleanSyscall);
//         norm("\n------------------------\n");
//     }

//     #if DEBUG
//         norm("\nSyscall Pool Contents:");
//         for (int i = 0; i < SIZE_OF_SYSCALL_CODE * numSyscalls; ++i)
//         {
//             if (i % 16 == 0)
//             {
//                 BYTE* addr = pSyscallPool + i;
//                 std::cout << YELLOW"\n" << "0x" << std::hex << std::setw(4) << std::setfill('0') << (void*)addr << CYAN": ";
//             }
//             else std::cout << std::hex << std::setw(2) << std::setfill('0') << CYAN"" << std::setw(2) << std::setfill('0') << (int)pSyscallPool[i] << " ";
//         }
//         std::cout << RESET"\n";
//     #endif

// /////////////////////////////////////////////////////////////////////////////////////////////////////////
//     norm(YELLOW"==============================================\n");

//     char buffer[] = "!!!!Hello from NtWriteFile syscall!!!\n";
//     ULONG length = sizeof(buffer) - 1;

//     void* status = SysFunction("NtWriteFile", ((DWORD)-11), nullptr, nullptr, nullptr, &ioStatusBlock, buffer, length, nullptr, nullptr);

//     if(status == (void*)(~0ull))
//     {
//         fuk("SysFunction failed\n");
//         return 1;
//     }

//     if((NTSTATUS)uintptr_t(status) == 0) ok("NtWriteFile call successful!");
//     else
//     {
//         fuk("NtWriteFile call failed!\n");
//         return 1;
//         fuk("Status; 0x", std::hex, status,  "\n");
//     }

//     norm(YELLOW"\n==============================================\n");
// // // //////////////////////////////////////////////////////////////////////////////////////////////////////////

//     HANDLE fileHandle = nullptr;
//     UNICODE_STRING fileName;
//     OBJECT_ATTRIBUTES objAttr;

//     // Create full path with windows prefix
//     WCHAR filePath[260] = L"\\??\\";
//     WCHAR currentDir[260];
//     ((pGetCurrentDirectoryW)sGhostFn.pGetCurrentDirectoryW)(260, currentDir);
//     wcscat_s(filePath, 260, currentDir);
//     wcscat_s(filePath, 260, L"\\testfile.txt");
    
//     fileName.Buffer = filePath;
//     fileName.Length = wcslen(filePath) * sizeof(WCHAR);
//     fileName.MaximumLength = fileName.Length + sizeof(WCHAR);

//     InitializeObjectAttributes(&objAttr, &fileName, 0x00000040L, NULL, NULL);

//     void* status1 = SysFunction("NtCreateFile",&fileHandle, FILE_GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, 0x00000080, 0x00000001, 0x00000005, 0x00000040 | 0x00000020,NULL,0);

//     if(status == (void*)(~0ull))
//     {
//         fuk("SysFunction failed\n");
//         return 1;
//     }

//     if((NTSTATUS)(uintptr_t(status1)) != 0)
//     {
//         fuk("Failed to create test file! Status: ", std::hex, "0x", (NTSTATUS)(uintptr_t(status1)));
//         return 1;
//     }
//     ok("File created successfully");

//     norm(YELLOW"\n==============================================\n");
// //     //////////////////////////////////////////////////////////////////////////////////////////////////////////

//     norm("DONE :)\n");
//     #if DEBUG_FILE
//         details::close_log_file();
//     #endif

    norm("\n");ok("BYE");
    return 0;
}

void* FindExportAddress(HMODULE hModule, const char* funcName)
{
norm(YELLOW"\n###########################");

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* nameRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* ordRVAs = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
norm(YELLOW"\n$$$$$$$$$$$$$$$$$$$$$$$$$$$");
    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
    {
        char* funcNameFromExport = (char*)((BYTE*)hModule + nameRVAs[i]);
        if (strcmp(funcNameFromExport, funcName) == 0)
        {
            DWORD funcRVA = funcRVAs[ordRVAs[i]];
            return (void*)((BYTE*)hModule + funcRVA);
        }
    }

    //fuk("Failed to find export address of: ", funcName, "\tGetlastError message -> ", GetLastError(), "\n");
    fuk("Failed to find export address of: ", funcName, "\tGetlastError message -> \n");
    return nullptr;
}
