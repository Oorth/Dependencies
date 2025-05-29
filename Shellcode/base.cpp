#include <windows.h>
#include <winternl.h>

#pragma region Shellcode

#pragma code_seg(push, ".stub")


    #pragma region Shellcode_resources

    #define S_OK ((HRESULT)0L)                                                  // Common HRESULT for success
    #define STRSAFE_E_INSUFFICIENT_BUFFER ((HRESULT)0x8007007AL)                // From strsafe.h

    #define PASTE_INTERNAL(a, b) a##b
    #define PASTE(a, b) PASTE_INTERNAL(a, b)
    #define LOG_W(fmt_literal, ...) \
        do \
        { \
            __declspec(allocate(".stub")) static const WCHAR PASTE(_fmt_str_, __LINE__)[] = fmt_literal; \
            \
            if(my_OutputDebugStringW) \
            { \
                int written = ShellcodeSprintfW(g_shellcodeLogBuffer, sizeof(g_shellcodeLogBuffer)/sizeof(WCHAR), PASTE(_fmt_str_, __LINE__), ##__VA_ARGS__); \
                if(written >= 0) \
                { \
                    my_OutputDebugStringW(g_shellcodeLogBuffer); \
                } else my_OutputDebugStringW(L"LOG_W formatting error or buffer too small."); \
            } \
        } while (0)

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    typedef int(WINAPI* pfnMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
    typedef void(WINAPI* pfnOutputDebugStringW)(LPCWSTR lpOutputString);
    typedef HMODULE(WINAPI* pfnLoadLibraryA)(LPCSTR lpLibFileName);
    typedef HANDLE(WINAPI* pfnCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    typedef BOOL(WINAPI* pfnCloseHandle)(HANDLE hObject);

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    __declspec(allocate(".stub")) static const WCHAR kNtdll[] = L"ntdll.dll";
    __declspec(allocate(".stub")) static const WCHAR kUsr32[] = L"user32.dll";
    __declspec(allocate(".stub")) static const WCHAR hKernelbase[] = L"kernelbase.dll";

    __declspec(allocate(".stub")) static const CHAR cOutputDebugStringWFunction[] = "OutputDebugStringW";
    __declspec(allocate(".stub")) static const CHAR cLoadLibraryAFunction[] = "LoadLibraryA";
    __declspec(allocate(".stub")) static const CHAR cCreateThreadFunction[] = "CreateThread";
    __declspec(allocate(".stub")) static const CHAR cCloseHandleFunction[] = "CloseHandle";

    __declspec(allocate(".stub")) pfnOutputDebugStringW my_OutputDebugStringW = nullptr;
    __declspec(allocate(".stub")) pfnLoadLibraryA my_LoadLibraryA = nullptr;
    __declspec(allocate(".stub")) pfnCreateThread my_CreateThread = nullptr;
    __declspec(allocate(".stub")) pfnCloseHandle my_CloseHandle = nullptr;

    __declspec(allocate(".stub")) static const WCHAR g_hexChars[] = L"0123456789ABCDEF";
    __declspec(allocate(".stub")) static WCHAR g_shellcodeLogBuffer[256];

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    __declspec(noinline) void __stdcall HelperSplitFilename(const WCHAR* full, SIZE_T fullLen, const WCHAR** outName, SIZE_T* outLen)
    {
        SIZE_T i = fullLen;
        while(i > 0)
        {
            WCHAR c = full[i - 1];
            if(c == L'\\' || c == L'/') break;
            --i;
        }
        *outName = full + i;
        *outLen  = fullLen - i;
    }

    __declspec(noinline) bool __stdcall isSame(const char* a, const char* b)
    {
        while(*a && *b)
        {
            char ca = *a, cb = *b;
            if(ca >= 'A' && ca <= 'Z') ca += ('a' - 'A');
            if(cb >= 'A' && cb <= 'Z') cb += ('a' - 'A');
            if(ca != cb) return false;
            ++a; ++b;
        }
        return (*a == '\0' && *b == '\0');
    }

    __declspec(noinline) bool __stdcall isSameW(const WCHAR* a, const WCHAR* b, SIZE_T len)
    {
        for(SIZE_T i = 0; i < len; i++)
        {
            WCHAR ca = a[i], cb = b[i];
            // tolower for ASCII A–Z
            if(ca >= L'A' && ca <= L'Z') ca += 32;
            if(cb >= L'A' && cb <= L'Z') cb += 32;
            if(ca != cb) return false;
        }
        return true;
    }


    __declspec(noinline) static WCHAR* __stdcall UllToHexW(unsigned __int64 val, WCHAR* buf_end, int max_chars)
    {
        // Helper to convert unsigned long long to hex string
        // Writes to buffer from right to left, returns pointer to start of written string in buffer
        if(max_chars <= 0) return buf_end;
        
        WCHAR* p = buf_end;
        *p = L'\0';
        if(val == 0 && max_chars > 0)
        {
            --p;
            *p = L'0';
            
            return p;
        }
        int count = 0;
        while(val > 0 && count < max_chars)
        {
            --p;
            *p = g_hexChars[val & 0xF];
            val >>= 4;
            count++;
        }
        return p;
    }

    __declspec(noinline) static WCHAR* __stdcall IntToDecW(int val, WCHAR* buf_end, int max_chars)
    {
        // Helper to convert integer to decimal string
        // Writes to buffer from right to left, returns pointer to start of written string in buffer
        if(max_chars <= 0) return buf_end;

        WCHAR* p = buf_end;
        *p = L'\0';
        if(val == 0 && max_chars > 0)
        {
            --p;
            *p = L'0';
            
            return p;
        }
        
        bool negative = false;
        if(val < 0)
        {
            negative = true;
            val = -val;                             // Make positive, careful with INT_MIN
            if(val < 0)
            {   
                // Overflow for INT_MIN
                // Handle INT_MIN specifically if needed, or just let it be large positive
            }
        }

        int count = 0;
        while(val > 0 && count < max_chars)
        {
            --p;
            *p = L'0' + (val % 10);
            val /= 10;
            count++;
        }
        if(negative && count < max_chars)
        {
            --p;
            *p = L'-';
        }
        return p;
    }

    __declspec(noinline) static int __cdecl ShellcodeSprintfW(LPWSTR pszDest, size_t cchDest, LPCWSTR pszFormat, ...)
    {
        // * Supported format specifiers:
        // * - %s  : Wide string (LPCWSTR)
        // * - %hs : ANSI string (LPCSTR)
        // * - %p  : Pointer value in hex
        // * - %X  : Unsigned int in hex
        // * - %hX : Unsigned short in hex 
        // * - %hx : Unsigned short in hex (lowercase)
        // * - %d  : Signed int in decimal
        // * - %%  : Literal percent sign
        // Returns number of characters written (excluding null terminator), or -1 on error/truncation
        
        if(!pszDest || !pszFormat || cchDest == 0) return -1;

        LPWSTR pDest = pszDest;
        LPCWSTR pFmt = pszFormat;
        size_t remaining = cchDest -1;      // Space for null terminator

        va_list args;
        va_start(args, pszFormat);

        WCHAR tempNumBuf[24];               // Buffer for number to string conversions (e.g., 64-bit hex + null)

        while(*pFmt && remaining > 0)
        {
            if(*pFmt == L'%')
            {
                pFmt++;

                switch(*pFmt)
                {
                    case L's': // Wide string
                    {
                        LPCWSTR str_arg = va_arg(args, LPCWSTR);
                        if(!str_arg) str_arg = L"(null)";
                        while(*str_arg && remaining > 0)
                        {
                            *pDest++ = *str_arg++;
                            remaining--;
                        }
                        break;
                    }

                    case L'h': // Potentially char* string OR short hex/dec
                        if(*(pFmt + 1) == L's')
                        { // %hs
                            pFmt++; // consume 's'
                            LPCSTR str_arg_a = va_arg(args, LPCSTR);
                            if(!str_arg_a) str_arg_a = "(null)"; // or some other indicator
                            while(*str_arg_a && remaining > 0)
                            {
                                *pDest++ = (WCHAR)(*str_arg_a++);
                                remaining--;
                            }
                        } 
                        else if(*(pFmt + 1) == L'X' || *(pFmt + 1) == L'x') 
                        { // %hX or %hx
                            pFmt++; // consume 'X' or 'x'
                            // Arguments smaller than int are promoted to int when passed via va_arg
                            unsigned short val_short_arg = (unsigned short)va_arg(args, unsigned int);
                            WCHAR* num_str_start = UllToHexW(val_short_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                            while(*num_str_start && remaining > 0)
                            {
                                *pDest++ = *num_str_start++;
                                remaining--;
                            }
                        }
                        // else if (*(pFmt + 1) == L'u') // handle %hu
                        // {
                        //     pFmt++; // consume 'u'
                        //     unsigned short val = (unsigned short)va_arg(args, unsigned int);
                        //     WCHAR* num_str_start = IntToDecW(val, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR) - 1), (sizeof(tempNumBuf)/sizeof(WCHAR) - 1));
                        //     while (*num_str_start && remaining > 0)
                        //     {
                        //         *pDest++ = *num_str_start++;
                        //         remaining--;
                        //     }
                        // }
                        // Add %hd for short decimal if needed
                        // else if(*(pFmt + 1) == L'd') { /* ... */ }
                        else
                        { // Not 'hs' or 'hX', treat as literal 'h'
                            if(remaining > 0) { *pDest++ = L'%'; remaining--; } // Re-emit the %
                            if(remaining > 0) { *pDest++ = L'h'; remaining--; } // Emit the h
                            // The character that was after 'h' (which wasn't s, X, or x) will be processed in the next loop iteration
                        }
                    break;

                    case L'p': // Pointer (hex) - uses unsigned __int64 for UllToHexW
                    {
                        unsigned __int64 val_ptr_arg = (unsigned __int64)va_arg(args, void*);
                        WCHAR* num_str_start = UllToHexW(val_ptr_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                        while(*num_str_start && remaining > 0)
                        {
                            *pDest++ = *num_str_start++;
                            remaining--;
                        }
                        break;
                    }

                    case L'X': // Hex unsigned int (can be extended for %llX for 64-bit)
                    {
                        unsigned __int64 val_arg;
                        if(*pFmt == L'p') val_arg = (unsigned __int64)va_arg(args, void*);
                        else val_arg = (unsigned __int64)va_arg(args, unsigned int); // Promote to 64-bit for UllToHexW

                        WCHAR* num_str_start = UllToHexW(val_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                        while(*num_str_start && remaining > 0)
                        {
                            *pDest++ = *num_str_start++;
                            remaining--;
                        }
                        break;
                    }
                    
                    case L'd': // Integer (decimal)
                    {
                        int val_arg = va_arg(args, int);
                        
                        WCHAR* num_str_start = IntToDecW(val_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                        while(*num_str_start && remaining > 0)
                        {
                            *pDest++ = *num_str_start++;
                            remaining--;
                        }
                        break;
                    }
                    
                    case L'%': // Literal percent
                    {                        __debugbreak();
                        if(remaining > 0) { *pDest++ = L'%'; remaining--; }
                        break;
                    }
                        
                    default: // Unknown format specifier, print literally
                    {
                        if(remaining > 0) { *pDest++ = L'%'; remaining--; }
                        if(*pFmt && remaining > 0) { *pDest++ = *pFmt; remaining--; } // Print the char after %
                        break;
                    }
                }
            } 
            else 
            {
                *pDest++ = *pFmt;
                remaining--;
            }
            if(*pFmt) pFmt++; // Move to next format char if not end of string
        }

        va_end(args);
        *pDest = L'\0'; // Null terminate

        if(*pFmt != L'\0') return -1; // Format string not fully processed (ran out of buffer)
        return (int)(pDest - pszDest); // Number of characters written
    }

    
    __declspec(noinline) static void* __stdcall ShellcodeFindExportAddress(HMODULE hModule, LPCSTR lpProcNameOrOrdinal, pfnLoadLibraryA pLoadLibraryAFunc)
    {
        //-----------

        if(!hModule) return nullptr;

        BYTE* base = (BYTE*)hModule;
        
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if(dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if(nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        IMAGE_DATA_DIRECTORY* pExportDataDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; // Use a pointer for clarity
        if (pExportDataDir->VirtualAddress == 0 || pExportDataDir->Size == 0) return nullptr;

        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + pExportDataDir->VirtualAddress);
        DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions); // RVAs to function bodies or forwarders

        //-----------

        // --- DIFFERENTIATE NAME VS ORDINAL ---
        bool isOrdinalLookup = false;
        WORD ordinalToFind = 0;

        #if defined(_WIN64)
            if (((ULONG_PTR)lpProcNameOrOrdinal >> 16) == 0)    // High bits of pointer are zero
            {
                isOrdinalLookup = true;
                ordinalToFind = LOWORD((ULONG_PTR)lpProcNameOrOrdinal);
            }
        #else // For 32-bit shellcode
            // For 32-bit, HIWORD macro is on a DWORD. ULONG_PTR might be 64-bit if compiled for x64 targeting x86.
            // Ensure lpProcNameOrOrdinal is treated as a 32-bit value for HIWORD.
            if (HIWORD((DWORD)(ULONG_PTR)lpProcNameOrOrdinal) == 0)
            { 
                isOrdinalLookup = true;
                ordinalToFind = LOWORD((DWORD)(ULONG_PTR)lpProcNameOrOrdinal);
            }
        #endif
        // --- END DIFFERENTIATION LOGIC ---

        DWORD funcRVA = 0; // RVA of the function/forwarder

        if (isOrdinalLookup)
        {
            if (ordinalToFind < exp->Base || (ordinalToFind - exp->Base) >= exp->NumberOfFunctions)
            {
                LOG_W(L"    [SFEA] Ordinal %hu is out of range (Base: %u, NumberOfFunctions: %u)", ordinalToFind, exp->Base, exp->NumberOfFunctions);
                return nullptr;
            }
            
            DWORD functionIndexInArray = ordinalToFind - exp->Base;
            if (functionIndexInArray >= exp->NumberOfFunctions) return nullptr;
            
            funcRVA = functions[functionIndexInArray];
        }
        else
        {
            // --- NAME LOOKUP PATH ---
            LPCSTR funcName = lpProcNameOrOrdinal;
            if (!funcName || *funcName == '\0') return nullptr;

            DWORD* nameRVAs = (DWORD*)(base + exp->AddressOfNames);          // RVAs to ASCII name strings
            WORD* nameOrdinals = (WORD*)(base + exp->AddressOfNameOrdinals); // Indices into the 'functions' array (NOT necessarily the export ordinals themselves)

            bool foundByName = false;
            for (DWORD i = 0; i < exp->NumberOfNames; ++i)
            {
                char* currentExportName = (char*)(base + nameRVAs[i]);
            
                if (isSame(currentExportName, funcName)) 
                {
                    WORD functionIndexInArray = nameOrdinals[i];            //index into the 'functions' array
            
                    // Bounds check for the index obtained from nameOrdinals
                    if (functionIndexInArray >= exp->NumberOfFunctions)
                    {
                        LOG_W(L"Name '%hs' gave an ordinal array index %hu out of bounds (%u).", funcName, functionIndexInArray, exp->NumberOfFunctions);
                        return nullptr;
                    }

                    funcRVA = functions[functionIndexInArray];
                    if (funcRVA == 0) return nullptr; // Should not happen for a named export pointing to a valid index

                    foundByName = true;
                    break;
                }
            }
        
            if(!foundByName)
            {
                LOG_W(L"Name '%hs' not found in export table.", funcName);
                return nullptr;
            }
        }

        if (funcRVA == 0)
        {
            LOG_W(L"RVA for %p in module 0x%p is zero.", lpProcNameOrOrdinal, hModule);
            return nullptr; // No valid RVA found
        } 

        BYTE* addr = base + funcRVA;

        // Check if this RVA points within the export directory itself (indicates a forwarded export)
        if (funcRVA >= pExportDataDir->VirtualAddress && funcRVA < (pExportDataDir->VirtualAddress + pExportDataDir->Size)) 
        {
            // This is a forwarder string like "OTHERDLL.OtherFunction" or "OTHERDLL.#123" 
            char* originalForwarderString = (char*)addr; // The RVA points to this string
            LOG_W(L"    [SFEA] Proc %p from module 0x%p is forwarded to: '%hs'", lpProcNameOrOrdinal, hModule, originalForwarderString);

            if (!pLoadLibraryAFunc)
            {
                LOG_W(L"    [SFEA] pLoadLibraryAFunc is nullptr, cannot resolve forwarder for %hs", originalForwarderString);
                return nullptr;
            }

            // --- PARSING: Work with a local, writable copy ---
            char localForwarderBuffer[256];
            UINT k_copy = 0;
            
            char* pOrig = originalForwarderString;
            while (*pOrig != '\0' && k_copy < (sizeof(localForwarderBuffer) - 1))
            {
                localForwarderBuffer[k_copy++] = *pOrig++;
            }
            localForwarderBuffer[k_copy] = '\0';


            char* dotSeparatorInLocal = nullptr;
            char* tempParserPtr = localForwarderBuffer;

            while (*tempParserPtr != '\0') 
            {
                if (*tempParserPtr == '.')
                {
                    dotSeparatorInLocal = tempParserPtr;
                    break;
                }
                ++tempParserPtr;
            }
            if (!dotSeparatorInLocal || dotSeparatorInLocal == localForwarderBuffer) { LOG_W(L"    [SFEA] Malformed forwarder string (in copy): '%hs'", localForwarderBuffer); return nullptr; }


            *dotSeparatorInLocal = '\0'; 
            char* forwardedFuncNameOrOrdinalStr = dotSeparatorInLocal + 1;
            if (*forwardedFuncNameOrOrdinalStr == '\0') { LOG_W(L"    [SFEA] Malformed forwarder string (nothing after dot in copy): '%hs'", localForwarderBuffer); return nullptr; }
            
            char* forwardedDllName = localForwarderBuffer;
            HMODULE hForwardedModule = pLoadLibraryAFunc(forwardedDllName);
            if (!hForwardedModule)
            {
                LOG_W(L"    [SFEA] Failed to load forwarded DLL: '%hs' (original forwarder was: '%hs')", forwardedDllName, originalForwarderString);
                return nullptr;
            }

            LOG_W(L"    [SFEA] Successfully loaded forwarded DLL: '%hs' to 0x%p", forwardedDllName, (void*)hForwardedModule);

            LPCSTR finalProcNameToResolve;
            if (*forwardedFuncNameOrOrdinalStr == '#') // Forwarding to an ordinal, e.g., "#123"
            {
                WORD fwdOrdinal = 0;
                char* pNum = forwardedFuncNameOrOrdinalStr + 1; // Skip '#'
                while (*pNum >= '0' && *pNum <= '9')
                {
                    fwdOrdinal = fwdOrdinal * 10 + (*pNum - '0');
                    pNum++;
                }

                // Check if any digits were actually parsed for the ordinal
                if (pNum == (forwardedFuncNameOrOrdinalStr + 1) && fwdOrdinal == 0)  // No digits after #, or #0 was not intended
                {
                    if (*(forwardedFuncNameOrOrdinalStr + 1) != '0' || *(forwardedFuncNameOrOrdinalStr + 2) != '\0')    // Allow "#0" but not "#" or "#abc"
                    {
                        LOG_W(L"    [SFEA] Invalid forwarded ordinal format (no valid number after #): %hs", forwardedFuncNameOrOrdinalStr);
                        return nullptr;
                    }
                }
                
                finalProcNameToResolve = (LPCSTR)(ULONG_PTR)fwdOrdinal;
                LOG_W(L"    [SFEA] Forwarding to ordinal %hu in '%hs'", fwdOrdinal, forwardedDllName);
            } 
            else // Forwarding to a name
            {
                finalProcNameToResolve = forwardedFuncNameOrOrdinalStr;
                LOG_W(L"    [SFEA] Forwarding to name '%hs' in '%hs'", finalProcNameToResolve, forwardedDllName);
            }

            return ShellcodeFindExportAddress(hForwardedModule, finalProcNameToResolve, pLoadLibraryAFunc);
        }       
        else return (void*)addr;
    }

    #pragma endregion

    __declspec(noinline) void __stdcall shellcode(LPVOID lpParameter)
    {
        #pragma region Shellcode_setup

        struct _LIBS
        {
            HMODULE hHookedNtdll;
            HMODULE hUnhookedNtdll;
            HMODULE hKERNEL32;
            HMODULE hKERNELBASE;
            HMODULE hUsr32;
        }sLibs;

        typedef struct _MY_PEB_LDR_DATA
        {
            ULONG Length;
            BOOLEAN Initialized;
            PVOID  SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
        } MY_PEB_LDR_DATA, *MY_PPEB_LDR_DATA;

        typedef struct _LDR_DATA_TABLE_ENTRY
        {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
        } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;    


        #ifdef _M_IX86
            PEB* pPEB = (PEB*) __readfsdword(0x30);
        #else
            PEB* pPEB = (PEB*) __readgsqword(0x60);   
        #endif
        
        MY_PEB_LDR_DATA* pLdr = (MY_PEB_LDR_DATA*)pPEB->Ldr;
        auto head = &pLdr->InLoadOrderModuleList;
        auto current = head->Flink;    // first entry is the EXE itself
        
        //walk load‑order
        while(current != head)
        {
            auto entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if(entry->BaseDllName.Buffer)
            {
                const WCHAR* namePtr;
                SIZE_T nameLen;

                HelperSplitFilename(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(WCHAR), &namePtr, &nameLen);

                SIZE_T k32len = sizeof(kUsr32)/sizeof(WCHAR) - 1;
                if(nameLen == k32len && isSameW(namePtr, kUsr32, k32len)) sLibs.hUsr32 = (HMODULE)entry->DllBase;

                k32len = sizeof(hKernelbase)/sizeof(WCHAR) - 1;
                if(nameLen == k32len && isSameW(namePtr, hKernelbase, k32len)) sLibs.hKERNELBASE = (HMODULE)entry->DllBase;

                k32len = sizeof(kNtdll)/sizeof(WCHAR) - 1;
                if(nameLen == k32len && isSameW(namePtr, kNtdll, k32len)) sLibs.hHookedNtdll = (HMODULE)entry->DllBase;
            }
            current = current->Flink;
        }
        if(sLibs.hUsr32 == NULL || sLibs.hKERNELBASE == NULL) __debugbreak();
        
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        my_OutputDebugStringW = (pfnOutputDebugStringW)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cOutputDebugStringWFunction, my_LoadLibraryA);
        if(my_OutputDebugStringW == NULL) __debugbreak();

        my_LoadLibraryA = (pfnLoadLibraryA)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cLoadLibraryAFunction, my_LoadLibraryA);
        if(my_LoadLibraryA == NULL) __debugbreak();

        my_CreateThread = (pfnCreateThread)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cCreateThreadFunction, my_LoadLibraryA);
        if(my_CreateThread == NULL) __debugbreak();

        my_CloseHandle = (pfnCloseHandle)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cCloseHandleFunction, my_LoadLibraryA);
        if(my_CloseHandle == NULL) __debugbreak();
            
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        __declspec(allocate(".stub")) static const WCHAR s2[] = L"Hello from injected shellcode!";
        ShellcodeSprintfW(g_shellcodeLogBuffer, sizeof(g_shellcodeLogBuffer)/sizeof(WCHAR), s2);
        
        #pragma endregion

        

        LOG_W(L"[END_OF_SHELLCODE]");
        // __debugbreak();
    }

#pragma code_seg(pop)
#pragma endregion