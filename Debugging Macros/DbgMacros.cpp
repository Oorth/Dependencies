//cl.exe /EHsc .\DbgMacros.cpp /link /OUT:DbgMacros.exe
/*******************************************************************************
 * Debugging Macros Usage:
 * 
 * This file provides color-coded debugging macros for console output.
 * When DEBUG is set to 1, the following macros are available:
 * 
 * ok(...)   - Prints in green with [+] prefix
 *             Example: ok("Success: ", value);
 * 
 * fuk(...)  - Prints in red with [!] prefix and suffix
 *             Example: fuk("Error: ", error_code);
 * 
 * warn(...) - Prints in yellow with [o] prefix
 *             Example: warn("Warning: ", warning_msg);
 * 
 * norm(...) - Prints without color or prefix
 *             Example: norm("Regular message");
 * 
 * Features:
 * - Supports multiple arguments
 * - Handles stream manipulators (std::dec, std::hex, etc.)
 * - Automatically resets color after each message
 * - All macros become no-ops when DEBUG is set to 0
 ******************************************************************************/

#define DEBUG 1

#if DEBUG
    #include <iostream>
#endif
////////////////////////////////////////////////////////////////////////////////

#if DEBUG
    #define GREEN "\033[32m"
    #define RED "\033[31m"
    #define YELLOW "\033[33m"
    #define RESET "\033[0m"
    
    #define ok(...) details::log(GREEN " [+] ", ##__VA_ARGS__)
    #define fuk(...) details::log(RED " [!] ", ##__VA_ARGS__, " [!] ")
    #define warn(...) details::log(YELLOW " [o] ", ##__VA_ARGS__)
    #define norm(...) details::log("", ##__VA_ARGS__)
#else
    #define ok(...)
    #define fuk(...)
    #define warn(...)
    #define norm(...)
#endif

#if DEBUG
namespace details
{
    void log_arg(std::ostream& os) { os << RESET; }

    template <typename T, typename... Args>
    void log_arg(std::ostream& os, const T& arg, Args... args)
    {
        os << arg;
        log_arg(os, args...);
    }

    void log_arg(std::ostream& os, std::ostream& (*manip)(std::ostream&)) { manip(os); }

    template <typename T>
    void log(const char* prefix, const T& single_arg)
    {
        std::cout << prefix;
        log_arg(std::cout, single_arg);
        std::cout << std::endl;
    }

    template <typename... Args>
    void log(const char* prefix, const char* msg, Args... args)
    {
        std::cout << prefix << msg;
        log_arg(std::cout, args...);
        std::cout << std::endl;
    }

    template <typename... Args>
    void log(const char* prefix, const char* msg, Args... args, const char* suffix)
    {
        std::cout << prefix << msg;
        log_arg(std::cout, args...);
        std::cout << suffix << std::endl;
    }
}
#endif

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