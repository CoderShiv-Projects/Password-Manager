// Tiny dependency-free test harness (so the project needs no test library).
#pragma once
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace ppm_test {

struct Case { const char* name; void (*fn)(); };
inline std::vector<Case>& registry() { static std::vector<Case> r; return r; }
inline int& failures() { static int f = 0; return f; }
struct Registrar { Registrar(const char* n, void (*f)()) { registry().push_back({n, f}); } };

inline void fail(const char* file, int line, const std::string& what) {
    ++failures();
    std::cerr << "    FAILED " << file << ":" << line << "  " << what << "\n";
}

}  // namespace ppm_test

#define TEST(name) \
    static void name(); \
    static ppm_test::Registrar registrar_##name(#name, name); \
    static void name()

#define CHECK(cond) do { if (!(cond)) ppm_test::fail(__FILE__, __LINE__, #cond); } while (0)
#define CHECK_EQ(a, b) do { auto va_ = (a); auto vb_ = (b); if (!(va_ == vb_)) { \
    std::ostringstream os_; os_ << #a " == " #b "  (got " << va_ << " vs " << vb_ << ")"; \
    ppm_test::fail(__FILE__, __LINE__, os_.str()); } } while (0)
