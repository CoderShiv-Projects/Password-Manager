#include "crypto_util.h"

#include <sodium.h>

namespace ppm {

bool initCrypto() {
    static const bool ok = (sodium_init() >= 0);
    return ok;
}

std::string randomHex(std::size_t nBytes) {
    initCrypto();
    std::string raw(nBytes, '\0');
    if (nBytes > 0) randombytes_buf(&raw[0], nBytes);
    std::string hex(nBytes * 2 + 1, '\0');
    sodium_bin2hex(&hex[0], hex.size(), reinterpret_cast<const unsigned char*>(raw.data()), nBytes);
    hex.resize(nBytes * 2);
    secureWipe(raw);
    return hex;
}

void secureWipe(std::string& s) {
    if (!s.empty()) sodium_memzero(&s[0], s.size());
    s.clear();
}

bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace ppm
