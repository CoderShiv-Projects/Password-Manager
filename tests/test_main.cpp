#include <exception>
#include <string>

#include "crypto_util.h"
#include "test_framework.h"

int main(int argc, char** argv) {
    ppm::initCrypto();
    const std::string filter = argc > 1 ? argv[1] : "";
    int ran = 0, failedTests = 0;
    for (const auto& c : ppm_test::registry()) {
        if (!filter.empty() && std::string(c.name).find(filter) == std::string::npos) continue;
        int before = ppm_test::failures();
        try { c.fn(); }
        catch (const std::exception& e) { ppm_test::fail(__FILE__, __LINE__, std::string("exception: ") + e.what()); }
        catch (...) { ppm_test::fail(__FILE__, __LINE__, "unknown exception"); }
        ++ran;
        bool ok = ppm_test::failures() == before;
        if (!ok) ++failedTests;
        std::cout << (ok ? "[ PASS ] " : "[ FAIL ] ") << c.name << "\n";
    }
    std::cout << "\n" << (ran - failedTests) << "/" << ran << " tests passed\n";
    return failedTests == 0 ? 0 : 1;
}
