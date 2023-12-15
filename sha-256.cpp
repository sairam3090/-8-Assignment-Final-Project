#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

// SHA-256 constants
const uint32_t k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// SHA-256 functions
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) ((x) >> (n))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

// SHA-256 class
class SHA256 {
public:
  SHA256();
  void update(const std::string &input);
  std::string final();

private:
  uint32_t h[8];
  std::vector<uint8_t> buffer;
  uint64_t length;
  void transform();
};

// SHA-256 constructor
SHA256::SHA256() {
  h[0] = 0x6a09e667;
  h[1] = 0xbb67ae85;
  h[2] = 0x3c6ef372;
  h[3] = 0xa54ff53a;
  h[4] = 0x510e527f;
  h[5] = 0x9b05688c;
  h[6] = 0x1f83d9ab;
  h[7] = 0x5be0cd19;
  length = 0;
}

// SHA-256 update function
void SHA256::update(const std::string &input) {
  for (char c : input) {
    buffer.push_back(static_cast<uint8_t>(c));
    length += 8;
    if (buffer.size() == 64) {
      transform();
      buffer.clear();
    }
  }
}

// SHA-256 final function
std::string SHA256::final() {
  // Padding
  buffer.push_back(0x80);
  while (buffer.size() % 64 != 56) {
    buffer.push_back(0x00);
  }
  // Length
  for (int i = 7; i >= 0; --i) {
    buffer.push_back((length >> (i * 8)) & 0xFF);
  }
  // Transform
  transform();
  // Output
  std::stringstream ss;
  for (int i = 0; i < 8; ++i) {
    ss << std::setfill('0') << std::setw(8) << std::hex << h[i];
  }
  return ss.str();
}

// SHA-256 transform function
void SHA256::transform() {
  for (size_t i = 0; i < buffer.size(); i += 64) {
    uint32_t w[64];
    for (int j = 0; j < 16; ++j) {
      w[j] = (buffer[i + j * 4] << 24) | (buffer[i + j * 4 + 1] << 16) |
             (buffer[i + j * 4 + 2] << 8) | buffer[i + j * 4 + 3];
    }
    for (int j = 16; j < 64; ++j) {
      w[j] = SIG1(w[j - 2]) + w[j - 7] + SIG0(w[j - 15]) + w[j - 16];
    }

    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    uint32_t f = h[5];
    uint32_t g = h[6];
    uint32_t hh = h[7];

    for (int j = 0; j < 64; ++j) {
      uint32_t t1 = hh + EP1(e) + CH(e, f, g) + k[j] + w[j];
      uint32_t t2 = EP0(a) + MAJ(a, b, c);
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }
}

int main() {
  // Downloading the book of Mark
  std::string url =
      "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892";
  std::ifstream ifs(url, std::ios::binary);
  std::string mark_book((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());

  // Calculate SHA-256 hash
  SHA256 sha256;
  sha256.update(mark_book);
  std::string hash_result = sha256.final();

  // Output the hash
  std::cout << "The SHA-256 hash of the Mark's book is:" << hash_result
            << std::endl;

  return 0;
}
