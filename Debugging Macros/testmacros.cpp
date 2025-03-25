//cl.exe /EHsc .\testmacros.cpp /link /OUT:testmacros.exe
#define DEBUG 1
#define DEBUG_VECTOR 1
#define DEBUG_FILE 1
#include "DbgMacros.h"

#if DEBUG_VECTOR
    #include <iostream>
#endif

int main()
{    
    void* a = (void*)10;
    int i = 1;

    ok(i);
    ok("just text");
    fuk("Error str");
    warn("warning str");
    norm("normal");
    ok("int -> ", std::dec, reinterpret_cast<intptr_t>(a), " and the Hex -> 0x", a );
    fuk("int -> ", std::dec, reinterpret_cast<intptr_t>(a), " and the Hex -> 0x", a );
    warn("int -> ", std::dec, reinterpret_cast<intptr_t>(a), " and the Hex -> 0x", a );

    #if DEBUG_VECTOR
        std::cout << "\nLogged messages in vector:\n";
        for (const auto& msg : details::logged_messages) std::cout << msg << std::endl;
    #endif

    #if DEBUG_FILE
        details::close_log_file();              // Add this line at the end
    #endif
    return 0;
}