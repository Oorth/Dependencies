/*******************************************************************************
 * Debugging Macros Usage:
 * 
 * ==========================================================================
 * !!!!Include a #define DEBUG 0/1 in your code to print to console!!!!
 * This header may include iostream depending on the DEBUG
 * 
 * 
 * !!!!Include a #define DEBUG_VECTOR 0/1 in your code to store to a vector!!!!
 * can be accessed as -> for (const auto& msg : details::logged_messages) std::cout << msg << std::endl;  //example
 * 
 * 
 * !!!!Include a #define DEBUG_FILE 0/1 in your code to store to a file called app.log!!!!
 *      #if DEBUG_FILE
 *          details::close_log_file();     // Add this line at the end
 *      #endif
 * 
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

    #if DEBUG_FILE
        #include <fstream>
        #include <iostream>
        #include <sstream>
    #endif
    ////////////////////////////////////////////////////////////////////////////////

    #if DEBUG || DEBUG_VECTOR || DEBUG_FILE
        #define GREEN "\033[32m"
        #define RED "\033[31m"
        #define YELLOW "\033[33m"
        #define CYAN "\033[96m"
        #define RESET "\033[0m"

        #define ok(...) details::log(GREEN "\n [+] ", ##__VA_ARGS__)
        #define fuk(...) details::log(RED "\n [!] ", ##__VA_ARGS__, " [!] ")
        #define warn(...) details::log(YELLOW "\n [o] ", ##__VA_ARGS__)
        #define norm(...) details::log("", ##__VA_ARGS__)
    #else
        #define ok(...)
        #define fuk(...)
        #define warn(...)
        #define norm(...)
    #endif

    #if DEBUG || DEBUG_VECTOR || DEBUG_FILE
        namespace details
        {
            #if DEBUG_VECTOR
                std::vector<std::string> logged_messages;
            #endif

            #if DEBUG_FILE
                std::ofstream log_output_file;
                bool log_file_opened = false;
                const char* log_file_name = "app.log";

                void open_log_file()
                {
                    if (!log_file_opened)
                    {
                        log_output_file.open(log_file_name, std::ios::app);
                        if (log_output_file.is_open()) log_file_opened = true;
                        // else std::cerr << "Error opening log file: " << log_file_name << std::endl;
                    }
                }

                void close_log_file()
                {
                    if (log_file_opened)
                    {
                        log_output_file.close();
                        log_file_opened = false;
                    }
                }

            #endif

            void log_arg(std::ostream& os){ os << RESET; }

            template <typename T, typename... Args>
            void log_arg(std::ostream& os, const T& arg, Args... args)
            {
                os << arg;
                log_arg(os, args...);
            }

            void log_arg(std::ostream& os, std::ostream& (*manip)(std::ostream&)) { manip(os); }

            // Added this overload back
            template <typename... Args>
            void log(const char* prefix_with_color, Args... args)
            {
                #if DEBUG
                    std::cout << prefix_with_color;
                    log_arg(std::cout, args...);
                    std::cout; // RESET is handled in log_arg
                #endif

                #if DEBUG_VECTOR
                    std::stringstream ss;
                    ss << prefix_with_color;
                    log_arg(ss, args...);
                    logged_messages.push_back(ss.str());
                #endif

                #if DEBUG_FILE
                    open_log_file();
                    if (log_file_opened)
                    {
                        std::stringstream ss_file;
                        const char* prefix_no_color = "";
                        if (prefix_with_color == GREEN " [+] ") prefix_no_color = " [+] ";
                        else if (prefix_with_color == RED " [!] ") prefix_no_color = " [!] ";
                        else if (prefix_with_color == YELLOW " [o] ") prefix_no_color = " [o] ";
                        ss_file << prefix_no_color;
                        log_arg(ss_file, args...);
                        log_output_file << ss_file.str();
                    }
                #endif
            }

            template <typename... Args>
            void log(const char* prefix_with_color, const char* msg, Args... args)
            {
                #if DEBUG
                    std::cout << prefix_with_color << msg;
                    log_arg(std::cout, args...);
                    std::cout << RESET;
                #endif

                #if DEBUG_VECTOR
                    std::stringstream ss;
                    ss << prefix_with_color << msg;
                    log_arg(ss, args...);
                    logged_messages.push_back(ss.str());
                #endif

                #if DEBUG_FILE
                    open_log_file();
                    if (log_file_opened)
                    {
                        std::stringstream ss_file;
                        const char* prefix_no_color = "";
                        if (prefix_with_color == GREEN " [+] ") prefix_no_color = " [+] ";
                        else if (prefix_with_color == RED " [!] ") prefix_no_color = " [!] ";
                        else if (prefix_with_color == YELLOW " [o] ") prefix_no_color = " [o] ";
                        ss_file << prefix_no_color << msg;
                        log_arg(ss_file, args...);
                        log_output_file << ss_file.str();
                    }
                #endif
            }
        }
    #endif
#endif