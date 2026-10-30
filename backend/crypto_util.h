// crypto_util.h - small helpers around libsodium used by several modules.
#pragma once
#include <cstddef>
#include <string>

namespace ppm {

// Initialises libsodium exactly once (thread-safe). Returns false if it failed.
bool initCrypto();

// Returns 2*nBytes lowercase hex characters built from nBytes of CSPRNG output.
std::string randomHex(std::size_t nBytes);

// Overwrites the string's bytes with zeros (sodium_memzero) and clears it.
void secureWipe(std::string& s);

// Constant-time equality (does not leak where the first difference is).
bool constantTimeEquals(const std::string& a, const std::string& b);

}  // namespace ppm
