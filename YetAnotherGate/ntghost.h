#pragma once

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define VOID            void

#if (_MSC_VER >= 800) || defined(_STDCALL_SUPPORTED)
    #define NTAPI __stdcall
#else
    #define _cdecl
    #define __cdecl
    #define NTAPI
#endif

#if ( defined(__midl) && (501 < __midl) )

    typedef [public] __int3264 INT_PTR, *PINT_PTR;
    typedef [public] unsigned __int3264 UINT_PTR, *PUINT_PTR;

    typedef [public] __int3264 LONG_PTR, *PLONG_PTR;
    typedef [public] unsigned __int3264 ULONG_PTR, *PULONG_PTR;

#else
    #if defined(_WIN64)
        typedef __int64 INT_PTR, *PINT_PTR;
        typedef unsigned __int64 UINT_PTR, *PUINT_PTR;

        typedef __int64 LONG_PTR, *PLONG_PTR;
        typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;

        #define __int3264   __int64

    #else
        typedef _W64 int INT_PTR, *PINT_PTR;
        typedef _W64 unsigned int UINT_PTR, *PUINT_PTR;

        typedef _W64 long LONG_PTR, *PLONG_PTR;
        typedef _W64 unsigned long ULONG_PTR, *PULONG_PTR;

        #define __int3264   __int32

    #endif
#endif // midl64

#define WINAPI      __stdcall

#ifndef DECLSPEC_IMPORT
    #if (defined(_M_IX86) || defined(_M_IA64) || defined(_M_AMD64) || defined(_M_ARM) || defined(_M_ARM64)) && !defined(MIDL_PASS)
        #define DECLSPEC_IMPORT __declspec(dllimport)
    #else
        #define DECLSPEC_IMPORT
    #endif
#endif

#if !defined(WINBASEAPI)
#if !defined(_KERNEL32_)
#define WINBASEAPI DECLSPEC_IMPORT
#else
#define WINBASEAPI
#endif
#endif

#define va_start __crt_va_start
#define va_arg   __crt_va_arg
#define va_end   __crt_va_end
#define va_copy(destination, source) ((destination) = (source))

#define CONTAINING_RECORD(address, type, field) ((type *)( \
(PCHAR)(address) - \
(ULONG_PTR)(&((type *)0)->field)))
    

// Forward declarations
struct _IMAGE_NT_HEADERS64;
struct _IMAGE_NT_HEADERS32;
typedef struct _IMAGE_NT_HEADERS64 *PIMAGE_NT_HEADERS64;
typedef struct _IMAGE_NT_HEADERS32 *PIMAGE_NT_HEADERS32;

#ifdef _WIN64
    typedef struct _IMAGE_NT_HEADERS64          IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;
#else
    typedef struct _IMAGE_NT_HEADERS32          IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;
#endif

#ifndef InitializeObjectAttributes
    #define InitializeObjectAttributes( p, n, a, r, s )     \
    {                                                       \
        (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
        (p)->RootDirectory = r;                             \
        (p)->Attributes = a;                                \
        (p)->ObjectName = n;                                \
        (p)->SecurityDescriptor = s;                        \
        (p)->SecurityQualityOfService = NULL;               \
    }
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Basic integer types and their pointers
typedef signed char         INT8, *PINT8;
typedef signed short        INT16, *PINT16;
typedef signed int          INT32, *PINT32;
typedef signed __int64      INT64, *PINT64;
typedef unsigned char       UINT8, *PUINT8;
typedef unsigned short      UINT16, *PUINT16;
typedef unsigned int        UINT32, *PUINT32;
typedef unsigned __int64    UINT64, *PUINT64;

// Standard integer types
typedef short SHORT;
typedef long LONG;
typedef int INT;
typedef double LONGLONG;
typedef unsigned int UINT;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef unsigned char BYTE;
typedef unsigned char BOOLEAN;
typedef unsigned short USHORT;
typedef unsigned long long ULONGLONG;

// Pointer types for basic integers
typedef SHORT *PSHORT;
typedef LONG *PLONG;
typedef WORD *PWORD;
typedef DWORD *PDWORD;
typedef ULONG *PULONG;
typedef BYTE *PBYTE, *LPBYTE;

// Size types
typedef ULONG_PTR SIZE_T, *PSIZE_T;
typedef LONG_PTR SSIZE_T, *PSSIZE_T;

// Character types
#ifndef _MAC
    typedef wchar_t WCHAR;    // wc,   16-bit UNICODE character
#endif
typedef char CHAR;

// Character types and strings
typedef CHAR *PCHAR, *LPCH, *PCH, *NPSTR, *LPSTR;
typedef const CHAR *LPCCH, *PCCH, *LPCSTR, *PCSTR;
typedef WCHAR *PWCHAR, *LPWCH, *PWCH, *PWSTR, *LPWSTR, *NWPSTR;
typedef const WCHAR *LPCWCH, *PCWCH, *LPCWSTR, *PCWSTR;

// Handle and pointer types
typedef void* PVOID;
typedef void* LPVOID;
typedef void* HANDLE;
typedef HANDLE* PHANDLE;
typedef void *HMODULE;
typedef void *HINSTANCE;
typedef void *HWND;

// Miscellaneous
typedef int BOOL;
typedef long NTSTATUS;
typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK *PACCESS_MASK;

#define NT_SUCCESS(x) ((NTSTATUS)(x) >= 0)

#if defined(MIDL_PASS)
    typedef struct _LARGE_INTEGER
    {
        LONGLONG QuadPart;
    } LARGE_INTEGER;
#else // MIDL_PASS
    typedef union _LARGE_INTEGER
    {
        struct
        {
            DWORD LowPart;
            LONG HighPart;
        } DUMMYSTRUCTNAME;
        struct
        {
            DWORD LowPart;
            LONG HighPart;
        } u;
        LONGLONG QuadPart;
    } LARGE_INTEGER;
#endif //MIDL_PASS
typedef LARGE_INTEGER *PLARGE_INTEGER;

#ifdef _MAC
// Forward declarations for Windows API types
#ifndef DECLARE_HANDLE
    #define DECLARE_HANDLE(name) struct name##__; typedef struct name##__ *name
#endif
#endif

typedef char CHAR;
typedef WCHAR *PWCHAR, *LPWCH, *PWCH;
typedef CHAR *PCHAR, *LPCH, *PCH;
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _IMAGE_DATA_DIRECTORY
{
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER
{
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

// Minimal LIST_ENTRY
typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, *PLIST_ENTRY;

// Minimal UNICODE_STRING
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// Full LDR_DATA_TABLE_ENTRY with all three list links
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... you can omit the rest ...
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// Full PEB_LDR_DATA with all three list heads
typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID  SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    // ... omit the rest ...
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// Minimal PEB just up to the Ldr pointer
typedef struct _PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    // no other fields needed
} PEB, *PPEB;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
    #pragma warning(push)
    #pragma warning(disable: 4201) // we'll always use the Microsoft compiler
        union 
        {
            NTSTATUS Status;
            PVOID Pointer;
        } DUMMYUNIONNAME;
    
        #pragma warning(pop)
        ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _IMAGE_DOS_HEADER
{      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

// #if defined(__cplusplus)
// #define EXTERN_C extern "C"
// #else
// #define EXTERN_C
// #endif

//////////////////////////////////////////////////////////////functions///////////////////////////////////////////////

// WINBASEAPI HANDLE WINAPI GetCurrentProcess(VOID);
// WINBASEAPI BOOL WINAPI CloseHandle(HANDLE hObject);
// LPVOID WINAPI VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
// DWORD WINAPI GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
// BOOL WINAPI VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
// DWORD WINAPI GetLastError(void);

//////////////////////////////////////////////////////////////FOR WRITE FILE///////////////////////////////////////////////
#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory
#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory
#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe
#define FILE_READ_EA              ( 0x0008 )    // file & directory
#define FILE_WRITE_EA             ( 0x0010 )    // file & directory
#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory
#define FILE_DELETE_CHILD         ( 0x0040 )    // directory
#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all
#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all
#define READ_CONTROL                     (0x00020000L)
#define STANDARD_RIGHTS_READ             (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE            (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE          (READ_CONTROL)

#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE    |\
    FILE_WRITE_DATA          |\
    FILE_WRITE_ATTRIBUTES    |\
    FILE_WRITE_EA            |\
    FILE_APPEND_DATA         |\
    0x00100000L)