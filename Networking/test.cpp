//cl /EHsc .\test.cpp /link /OUT:test.exe
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

LPCSTR dllPath_n = "network_lib.dll";

typedef int (*SendDataFunc)(const std::string&, const std::string&);
typedef std::string (*RecvDataFunc)(const std::string&);
typedef std::vector<unsigned char> (*RecvDataRawFunc)(const std::string&);

SendDataFunc send_data;
RecvDataFunc receive_data;
RecvDataRawFunc receive_data_raw;

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
    std::cout << "Failed to find export address of: " << funcName << std::endl;
    return nullptr;
}

void load_dll()                                             
{
    HMODULE N_dll = LoadLibraryA("network_lib.dll");
    if (N_dll == nullptr) std::cerr << "Failed to load DLL: " << GetLastError() << std::endl;

    receive_data_raw = (RecvDataRawFunc)FindExportAddress(N_dll, "?receive_data_raw@@YA?AV?$vector@EV?$allocator@E@std@@@std@@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@@Z");
    send_data = (SendDataFunc)FindExportAddress(N_dll, "?send_data@@YAHAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z");    
    receive_data = (RecvDataFunc)FindExportAddress(N_dll, "?receive_data@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AEBV12@@Z");
    
    if (receive_data_raw == nullptr || send_data == nullptr || receive_data == nullptr) std::cerr << "Failed to find export address of one or more functions." << std::endl;
}

int main()
{
    load_dll();
    std::vector <unsigned char> a;

    

    unsigned char c=170;
    for(int i=0; i<50 ; ++i, ++c)
    {
        send_data("target_data.rat", std::to_string(13 + i) + "!!!!!!!!!!!!!!!!!!!!!!!0");
        std::cout << "( " << c << " ) " << receive_data("target_data.rat") << std::endl;
        Sleep(100);
    }
    a = receive_data_raw("target_data.rat");
    std::cout << "2) "; for(unsigned char c : a) std::cout << c;

    std::cout << std::endl;
    std::cout << "3) "<< receive_data("target_data.rat") << std::endl;

    return 0;
}