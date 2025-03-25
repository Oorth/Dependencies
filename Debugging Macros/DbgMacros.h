/*******************************************************************************
 * Debugging Macros Usage:
 * 
 * ==========================================================================
 * !!!!Include a #define DEBUG 0/1 in your code to print to console!!!!
 * This header may include iostream depending on the DEBUG
 * 
 * !!!!Include a #define DEBUG_VECTOR 0/1 in your code to store to a vector!!!!
 * can be accessed as -> for (const auto& msg : details::logged_messages) std::cout << msg << std::endl;  //example
 * ==========================================================================
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
#ifndef DBGMACROS_H
#define DBGMACROS_H

    #if DEBUG
        #include <iostream>
    #endif

    #if DEBUG_VECTOR
        #include <vector>
        #include <sstream>
        #include <iomanip>
    #endif
    ////////////////////////////////////////////////////////////////////////////////

    #if DEBUG || DEBUG_VECTOR
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

    #if DEBUG || DEBUG_VECTOR // Include details namespace if either DEBUG or DEBUG_VECTOR is defined
        namespace details
        {
            #if DEBUG_VECTOR
                std::vector<std::string> logged_messages;
            #endif

            void log_arg(std::ostream& os) { os << RESET; }

            template <typename T, typename... Args>
            void log_arg(std::ostream& os, const T& arg, Args... args)
            {
                os << arg;
                log_arg(os, args...);
            }

            void log_arg(std::ostream& os, std::ostream& (*manip)(std::ostream&)) { manip(os); }

            template <typename... Args>
            void log(const char* prefix, Args... args)
            {
                #if DEBUG
                    std::cout << prefix;
                    log_arg(std::cout, args...);
                    std::cout << RESET << std::endl;
                #endif

                #if DEBUG_VECTOR
                    std::stringstream ss;
                    ss << prefix;
                    log_arg(ss, args...);
                    logged_messages.push_back(ss.str());
                #endif
            }

            template <typename... Args>
            void log(const char* prefix, const char* msg, Args... args)
            {
                #if DEBUG
                    std::cout << prefix << msg << " ";
                    log_arg(std::cout, args...);
                    std::cout << RESET << std::endl;
                #endif

                #if DEBUG_VECTOR
                    std::stringstream ss;
                    ss << prefix << msg << " ";
                    log_arg(ss, args...);
                    logged_messages.push_back(ss.str());
                #endif
            }

            template <typename... Args>
            void log(const char* prefix, const char* msg, Args... args, const char* suffix)
            {
                #if DEBUG
                    std::cout << prefix << msg << " ";
                    log_arg(std::cout, args...);
                    std::cout << suffix << RESET << std::endl;
                #endif

                #if DEBUG_VECTOR
                    std::stringstream ss;
                    ss << prefix << msg << " ";
                    log_arg(ss, args...);
                    ss << suffix;
                    logged_messages.push_back(ss.str());
                #endif
            }
        }
    #endif
#endif