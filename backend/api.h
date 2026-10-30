// api.h - HTTP layer: routes, validation, session handling, static frontend files.
#pragma once
#include <memory>
#include <string>

#include "storage.h"

namespace ppm {

struct ServerConfig {
    std::string host = "127.0.0.1";   // loopback only by default
    int port = 8080;                  // 0 = choose any free port (used by tests)
    std::string vaultPath = "data/vault.dat";
    std::string frontendDir = "frontend";
    KdfParams kdf = KdfParams::moderate();
    int idleTimeoutSeconds = 600;     // auto-lock after this much inactivity
    int maxFailedUnlocks = 5;         // then temporary lock-out
    int lockoutSeconds = 30;
    bool allowRemote = false;         // disables the Host-header check (not recommended)
};

class ApiServer {
public:
    explicit ApiServer(ServerConfig config);
    ~ApiServer();
    ApiServer(const ApiServer&) = delete;
    ApiServer& operator=(const ApiServer&) = delete;

    bool bind();            // false if the port is unavailable
    int port() const;       // actual port after bind()
    void run();             // blocks until stop()
    void waitUntilReady();
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace ppm
