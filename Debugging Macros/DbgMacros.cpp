#define DEBUG 1

#if DEBUG
    #include <iostream>
#endif
////////////////////////////////////////////////////////////////////////////////

#if DEBUG
    #define ok(...) details::log(" [+] ", ##__VA_ARGS__)
    #define fuk(...) details::log(" [-] ", ##__VA_ARGS__, " [!] ")
    #define warn(...) details::log(" [!] ", ##__VA_ARGS__)
#else
    #define ok(...)
    #define fuk(...)
    #define warn(...)
#endif

#if DEBUG
namespace details
{
    void log_arg(std::ostream& os) {}

    template <typename T, typename... Args>
    void log_arg(std::ostream& os, const T& arg, Args... args)
    {
        os << arg;
        log_arg(os, args...);
    }

    void log_arg(std::ostream& os, std::ostream& (*manip)(std::ostream&))
    {
        manip(os);
    }

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
        std::cout << prefix << msg << " ";
        log_arg(std::cout, args...);
        std::cout << std::endl;
    }

    template <typename... Args>
    void log(const char* prefix, const char* msg, Args... args, const char* suffix)
    {
        std::cout << prefix << msg << " ";
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
    ok("int -> ", std::dec, reinterpret_cast<intptr_t>(a), " and the Hex -> 0x", a );
    fuk("int -> ", std::dec, reinterpret_cast<intptr_t>(a), " and the Hex -> 0x", a );
    warn("int -> ", std::dec, reinterpret_cast<intptr_t>(a), " and the Hex -> 0x", a );

    return 0;
}