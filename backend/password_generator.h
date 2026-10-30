// password_generator.h - configurable password generator (libsodium CSPRNG).
#pragma once
#include <string>

namespace ppm {

struct GeneratorOptions {
    int length = 16;
    bool lowercase = true;
    bool uppercase = true;
    bool numbers = true;
    bool symbols = true;
};

struct GeneratorResult {
    bool ok = false;
    std::string password;
    std::string error;
};

class PasswordGenerator {
public:
    static constexpr int kMinLength = 8;
    static constexpr int kMaxLength = 128;

    // Returns an empty string when the options are valid, otherwise the reason.
    static std::string validate(const GeneratorOptions& opts);

    // Guarantees at least one character from every enabled class, then shuffles.
    static GeneratorResult generate(const GeneratorOptions& opts);

    static const std::string& lowercaseChars();
    static const std::string& uppercaseChars();
    static const std::string& numberChars();
    static const std::string& symbolChars();
};

}  // namespace ppm
