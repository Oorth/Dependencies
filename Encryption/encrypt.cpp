#define DEBUG 1

#include <vector>
#include <cstdint>
#include "DbgMacros.h"

// Function to encode data into alternate bits of a vector of DWORDs
std::vector<uint32_t> encodeAlternateBits(const std::vector<uint8_t>& data)
{
    std::vector<uint32_t> encodedData;
    uint32_t currentWord = 0;
    int bitIndex = 0;

    for (uint8_t byte : data)
    {
        for (int i = 0; i < 8; ++i)
        {
            if ((byte >> i) & 1)                        // Get the i-th bit of the byte
            { 
                currentWord |= (1 << (bitIndex * 2)); // Set the alternate bit
            }
            bitIndex++;
            if (bitIndex == 16)          // Fill a DWORD (using every other bit)
            {
                encodedData.push_back(currentWord);
                currentWord = 0;
                bitIndex = 0;
            }
        }
    }
    // Handle any remaining bits
    if (bitIndex > 0)
    {
        encodedData.push_back(currentWord);
    }
    return encodedData;
}

// Function to decode data from alternate bits of a vector of DWORDs
std::vector<uint8_t> decodeAlternateBits(const std::vector<uint32_t>& encodedData)
{
    std::vector<uint8_t> decodedData;
    uint8_t currentByte = 0;
    int bitIndex = 0;

    for (uint32_t word : encodedData)
    {
        for (int i = 0; i < 16; ++i) {
            if ((word >> (i * 2)) & 1) { // Get the alternate bit
                currentByte |= (1 << bitIndex);
            }
            bitIndex++;
            if (bitIndex == 8) { // Filled a byte
                decodedData.push_back(currentByte);
                currentByte = 0;
                bitIndex = 0;
            }
        }
    }
    return decodedData;
}

int main()
{
    std::vector<uint8_t> originalData = {'H', 'e', 'l', 'l', 'o'};
    
    norm("Original Data: ");
    for (char c : originalData)
    {
        norm(GREEN"", c);
    }
    norm("\n");

    std::vector<uint32_t> encoded = encodeAlternateBits(originalData);
    norm("Encoded Data (DWORDs): ");
    for (uint32_t val : encoded) 
    {
        norm(RED"", val, " ");
    }
    norm("\n");

    std::vector<uint8_t> decoded = decodeAlternateBits(encoded);
    norm("Decoded Data: ");
    for (char c : decoded)
    {
        norm(GREEN"", c);
    }
    norm("\n");

    return 0;
}