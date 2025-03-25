//cl.exe /EHsc .\testmacros.cpp /link /OUT:testmacros.exe
#define DEBUG 1
#define log_vector 1
#include "DbgMacros.h"

int main()
{    
    void* a = (void*)10;
    int i = 1;

    ok(i);
    ok("just text");
    norm("normal");
    ok("int -> ", std::dec, reinterpret_cast<intptr_t>(a), " and the Hex -> 0x", a );
    fuk("int -> ", std::dec, reinterpret_cast<intptr_t>(a), " and the Hex -> 0x", a );
    warn("int -> ", std::dec, reinterpret_cast<intptr_t>(a), " and the Hex -> 0x", a );

    #if log_vector
        std::cout << "\nLogged messages in vector:\n";
        for (const auto& msg : details::logged_messages) std::cout << msg << std::endl;
    #endif

    return 0;
}