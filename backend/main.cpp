// main.cpp - command-line parsing and server start-up.
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "api.h"
#include "crypto_util.h"

namespace fs = std::filesystem;

#ifndef PPM_SOURCE_DIR
#define PPM_SOURCE_DIR "."
#endif

static std::atomic<bool> g_stop{false};
static void onSignal(int) { g_stop = true; }

static void printHelp() {
    std::cout <<
        "Personal Password Management and Account Credential Organization System\n"
        "College learning prototype - not security audited.\n\n"
        "Usage: password_manager [options]\n"
        "  --port N             port to listen on (default 8080)\n"
        "  --vault PATH         encrypted vault file (default <project>/data/vault.dat)\n"
        "  --frontend DIR       folder containing index.html, css/, js/\n"
        "  --kdf MODE           moderate (default, 256 MiB) | interactive (64 MiB); used when creating a vault\n"
        "  --idle-minutes N     auto-lock after N idle minutes (default 10)\n"
        "  --host ADDR          bind address (default 127.0.0.1; must be loopback)\n"
        "  --help               show this text\n";
}

int main(int argc, char** argv) {
    if (!ppm::initCrypto()) { std::cerr << "Error: libsodium could not be initialised.\n"; return 1; }

    ppm::ServerConfig cfg;
    cfg.vaultPath = (fs::path(PPM_SOURCE_DIR) / "data" / "vault.dat").string();
    std::string frontend;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) { std::cerr << "Missing value for " << name << "\n"; std::exit(2); }
            return argv[++i];
        };
        if (a == "--help" || a == "-h") { printHelp(); return 0; }
        else if (a == "--port") {
            cfg.port = std::atoi(next("--port").c_str());
            if (cfg.port < 1 || cfg.port > 65535) { std::cerr << "Port must be 1-65535.\n"; return 2; }
        }
        else if (a == "--vault") cfg.vaultPath = next("--vault");
        else if (a == "--frontend") frontend = next("--frontend");
        else if (a == "--host") cfg.host = next("--host");
        else if (a == "--idle-minutes") {
            int m = std::atoi(next("--idle-minutes").c_str());
            if (m < 1 || m > 240) { std::cerr << "--idle-minutes must be 1-240.\n"; return 2; }
            cfg.idleTimeoutSeconds = m * 60;
        }
        else if (a == "--kdf") {
            std::string m = next("--kdf");
            if (m == "interactive") cfg.kdf = ppm::KdfParams::interactive();
            else if (m == "moderate") cfg.kdf = ppm::KdfParams::moderate();
            else { std::cerr << "--kdf must be 'moderate' or 'interactive'.\n"; return 2; }
        }
        else { std::cerr << "Unknown option: " << a << "\nTry --help.\n"; return 2; }
    }

    if (cfg.host != "127.0.0.1" && cfg.host != "localhost" && cfg.host != "::1") {
        std::cerr << "Refusing to bind to '" << cfg.host << "': this prototype only serves the local machine.\n";
        return 2;
    }

    // Locate the frontend folder (first candidate containing index.html wins).
    std::vector<fs::path> candidates;
    if (!frontend.empty()) candidates.push_back(frontend);
    candidates.push_back(fs::path(PPM_SOURCE_DIR) / "frontend");
    candidates.push_back("frontend");
    candidates.push_back("../frontend");
    for (const auto& c : candidates) {
        std::error_code ec;
        if (fs::exists(c / "index.html", ec)) { cfg.frontendDir = c.string(); break; }
    }
    if (!fs::exists(fs::path(cfg.frontendDir) / "index.html")) {
        std::cerr << "Error: could not find frontend/index.html. Use --frontend <folder>.\n";
        return 1;
    }

    ppm::ApiServer server(cfg);
    if (!server.bind()) {
        std::cerr << "Error: could not listen on " << cfg.host << ":" << cfg.port
                  << ". The port may be in use - try --port " << (cfg.port + 1) << ".\n";
        return 1;
    }

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    std::thread watcher([&] {
        while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        server.stop();
    });

    std::cout << "Personal Password Management and Account Credential Organization System\n"
              << "College learning prototype - not security audited. Use fake data only.\n\n"
              << "  Vault file : " << fs::absolute(cfg.vaultPath).string() << "\n"
              << "  Frontend   : " << fs::absolute(cfg.frontendDir).string() << "\n"
              << "  Open       : http://127.0.0.1:" << server.port() << "\n\n"
              << "Press Ctrl+C to stop.\n" << std::flush;

    server.run();
    g_stop = true;
    watcher.join();
    std::cout << "Server stopped.\n";
    return 0;
}
