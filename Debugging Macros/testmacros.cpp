//cl.exe /EHsc .\testmacros.cpp /link /OUT:testmacros.exe
#define DEBUG 1
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

    return 0;
}