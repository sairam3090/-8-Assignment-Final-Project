#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <cmath>

class SHA256 {
public:
    std::string hash(const std::string& message) {
        std::vector<uint32_t> hashValues = initialHashValues;

        std::string paddedMessage = padMessage(message);
        for (size_t i = 0; i < paddedMessage.size(); i += 64) {
            processBlock(paddedMessage.substr(i, 64), hashValues);
        }

        std::stringstream ss;
        for (uint32_t value : hashValues) {
            ss << std::hex << std::setw(8) << std::setfill('0') << value;
        }

        return ss.str();
    }

private:
    static const std::vector<uint32_t> initialHashValues;
    static const std::vector<uint32_t> k;

    std::string padMessage(const std::string& message);
    void processBlock(const std::string& block, std::vector<uint32_t>& hashValues);
    uint32_t rightRotate(uint32_t value, uint32_t count);
};

const std::vector<uint32_t> SHA256::initialHashValues = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

const std::vector<uint32_t> SHA256::k = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    
};

std::string SHA256::padMessage(const std::string& message) {
    
}

void SHA256::processBlock(const std::string& block, std::vector<uint32_t>& hashValues) {
    
}

uint32_t SHA256::rightRotate(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32 - count));
}

int main() {
    // Read the book of Mark from a local file
    std::ifstream file("mark_book.txt");
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open the file." << std::endl;
        return 1;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string markBook = buffer.str();

    // Calculate SHA-256 hash
    SHA256 sha256;
    std::string hashed = sha256.hash(markBook);

    std::cout << "The SHA-256 hash of the Mark's book is:" << std::endl;
    std::cout << hashed << std::endl;

    return 0;
}
