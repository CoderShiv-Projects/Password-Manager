#include <set>

#include "password_generator.h"
#include "test_framework.h"

using namespace ppm;

static bool hasAny(const std::string& pw, const std::string& set) {
    return pw.find_first_of(set) != std::string::npos;
}

TEST(generator_respects_length_and_classes) {
    for (int len : {8, 16, 64, 128}) {
        GeneratorOptions o; o.length = len;
        auto r = PasswordGenerator::generate(o);
        CHECK(r.ok);
        CHECK_EQ(int(r.password.size()), len);
        CHECK(hasAny(r.password, PasswordGenerator::lowercaseChars()));
        CHECK(hasAny(r.password, PasswordGenerator::uppercaseChars()));
        CHECK(hasAny(r.password, PasswordGenerator::numberChars()));
        CHECK(hasAny(r.password, PasswordGenerator::symbolChars()));
    }
}

TEST(generator_every_enabled_class_present_even_at_min_length) {
    for (int i = 0; i < 300; ++i) {
        GeneratorOptions o; o.length = 8;
        auto r = PasswordGenerator::generate(o);
        CHECK(r.ok);
        CHECK(hasAny(r.password, PasswordGenerator::lowercaseChars()) && hasAny(r.password, PasswordGenerator::uppercaseChars()) &&
              hasAny(r.password, PasswordGenerator::numberChars()) && hasAny(r.password, PasswordGenerator::symbolChars()));
    }
}

TEST(generator_single_class_only_uses_that_class) {
    GeneratorOptions o; o.length = 40; o.lowercase = false; o.uppercase = false; o.symbols = false;
    auto r = PasswordGenerator::generate(o);
    CHECK(r.ok);
    CHECK(r.password.find_first_not_of(PasswordGenerator::numberChars()) == std::string::npos);
    GeneratorOptions s; s.length = 30; s.lowercase = false; s.uppercase = false; s.numbers = false;
    auto rs = PasswordGenerator::generate(s);
    CHECK(rs.password.find_first_not_of(PasswordGenerator::symbolChars()) == std::string::npos);
}

TEST(generator_rejects_invalid_configurations) {
    GeneratorOptions o; o.length = 7;
    CHECK(!PasswordGenerator::generate(o).ok);
    o.length = 129;
    CHECK(!PasswordGenerator::generate(o).ok);
    o.length = 16; o.lowercase = o.uppercase = o.numbers = o.symbols = false;
    auto r = PasswordGenerator::generate(o);
    CHECK(!r.ok); CHECK(!r.error.empty()); CHECK(r.password.empty());
}

TEST(generator_outputs_differ) {
    std::set<std::string> seen;
    GeneratorOptions o; o.length = 24;
    for (int i = 0; i < 200; ++i) seen.insert(PasswordGenerator::generate(o).password);
    CHECK_EQ(seen.size(), std::size_t(200));
}
