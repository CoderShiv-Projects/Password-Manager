#include "password_generator.h"

#include <sodium.h>

#include <utility>
#include <vector>

#include "crypto_util.h"

namespace ppm {

const std::string& PasswordGenerator::lowercaseChars() { static const std::string s = "abcdefghijklmnopqrstuvwxyz"; return s; }
const std::string& PasswordGenerator::uppercaseChars() { static const std::string s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; return s; }
const std::string& PasswordGenerator::numberChars() { static const std::string s = "0123456789"; return s; }
const std::string& PasswordGenerator::symbolChars() { static const std::string s = "!@#$%^&*()-_=+[]{};:,.?/~"; return s; }

std::string PasswordGenerator::validate(const GeneratorOptions& o) {
    if (o.length < kMinLength || o.length > kMaxLength)
        return "Length must be between " + std::to_string(kMinLength) + " and " + std::to_string(kMaxLength) + ".";
    if (!o.lowercase && !o.uppercase && !o.numbers && !o.symbols)
        return "Select at least one character type.";
    return "";
}

// randombytes_uniform() returns an unbiased value in [0, bound) - no modulo bias.
static char pick(const std::string& set) {
    return set[randombytes_uniform(static_cast<uint32_t>(set.size()))];
}

GeneratorResult PasswordGenerator::generate(const GeneratorOptions& o) {
    GeneratorResult r;
    r.error = validate(o);
    if (!r.error.empty()) return r;
    if (!initCrypto()) { r.error = "Secure random generator is unavailable."; return r; }

    std::vector<const std::string*> classes;
    if (o.lowercase) classes.push_back(&lowercaseChars());
    if (o.uppercase) classes.push_back(&uppercaseChars());
    if (o.numbers) classes.push_back(&numberChars());
    if (o.symbols) classes.push_back(&symbolChars());

    std::string pool, out;
    for (const std::string* c : classes) {
        out.push_back(pick(*c));      // one guaranteed character per enabled class
        pool += *c;
    }
    while (static_cast<int>(out.size()) < o.length) out.push_back(pick(pool));

    for (std::size_t i = out.size() - 1; i > 0; --i)       // Fisher-Yates shuffle
        std::swap(out[i], out[randombytes_uniform(static_cast<uint32_t>(i + 1))]);

    r.ok = true;
    r.password = std::move(out);
    return r;
}

}  // namespace ppm
