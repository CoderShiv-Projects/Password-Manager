#include "api.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <vector>

#include "crypto_util.h"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "password_generator.h"
#include "password_manager.h"

namespace ppm {

using json = nlohmann::json;
using Clock = std::chrono::steady_clock;
using httplib::Request;
using httplib::Response;

namespace {

constexpr const char* kAppTitle = "Personal Password Management and Account Credential Organization System";
constexpr const char* kCookieName = "ppm_session";

std::size_t countCodePoints(const std::string& s) {
    std::size_t n = 0;
    for (unsigned char c : s) if ((c & 0xC0) != 0x80) ++n;
    return n;
}

void sendJson(Response& res, int status, const json& body) {
    res.status = status;
    res.set_content(body.dump(-1, ' ', false, json::error_handler_t::replace), "application/json; charset=utf-8");
}

void sendError(Response& res, int status, const std::string& code, const std::string& message,
               const std::string& field = "") {
    json e = {{"code", code}, {"message", message}};
    if (!field.empty()) e["field"] = field;
    sendJson(res, status, {{"error", e}});
}

int httpStatusFor(ErrorCode c) {
    switch (c) {
        case ErrorCode::Validation: return 400;
        case ErrorCode::NotFound: return 404;
        case ErrorCode::NothingToUndo: return 409;
        default: return 500;
    }
}

const char* codeNameFor(ErrorCode c) {
    switch (c) {
        case ErrorCode::Validation: return "validation_error";
        case ErrorCode::NotFound: return "not_found";
        case ErrorCode::NothingToUndo: return "nothing_to_undo";
        default: return "internal_error";
    }
}

void sendOpError(Response& res, const OpResult& r) {
    sendError(res, httpStatusFor(r.code), codeNameFor(r.code), r.message, r.field);
}

json metaToJson(const AccountMeta& m) {
    return {{"id", m.id}, {"website", m.website}, {"username", m.username}, {"category", m.category},
            {"createdAt", formatIso8601(m.createdAt)}, {"updatedAt", formatIso8601(m.updatedAt)},
            {"weakPassword", m.weak}, {"reusedPassword", m.reused}};
}

json statsToJson(const VaultStats& s, bool unsaved) {
    json cats = json::array();
    for (const auto& c : s.byCategory) cats.push_back({{"category", c.first}, {"count", c.second}});
    return {{"total", s.total}, {"weakPasswords", s.weak}, {"reusedPasswords", s.reused},
            {"undoDepth", s.undoDepth}, {"byCategory", cats}, {"unsavedChanges", unsaved}};
}

bool readJsonObject(const Request& req, Response& res, json& out) {
    std::string ct = toLowerAscii(req.get_header_value("Content-Type"));
    if (ct.rfind("application/json", 0) != 0) {
        sendError(res, 415, "unsupported_media_type", "Send the request body as application/json.");
        return false;
    }
    if (req.body.empty()) { sendError(res, 400, "invalid_json", "Request body is empty."); return false; }
    out = json::parse(req.body, nullptr, false);
    if (out.is_discarded()) { sendError(res, 400, "invalid_json", "Request body is not valid JSON."); return false; }
    if (!out.is_object()) { sendError(res, 400, "invalid_json", "Request body must be a JSON object."); return false; }
    return true;
}

bool optString(const json& body, const char* key, std::optional<std::string>& out, Response& res) {
    auto it = body.find(key);
    if (it == body.end()) return true;
    if (!it->is_string()) { sendError(res, 400, "validation_error", std::string(key) + " must be a string.", key); return false; }
    out = it->get<std::string>();
    return true;
}

bool readAccountInput(const json& body, AccountInput& in, Response& res) {
    return optString(body, "website", in.website, res) && optString(body, "username", in.username, res) &&
           optString(body, "password", in.password, res) && optString(body, "category", in.category, res);
}

std::string cookieValue(const Request& req, const std::string& name) {
    const std::string hdr = req.get_header_value("Cookie");
    const std::string key = name + "=";
    std::size_t pos = 0;
    while (pos < hdr.size()) {
        while (pos < hdr.size() && (hdr[pos] == ' ' || hdr[pos] == ';')) ++pos;
        if (hdr.compare(pos, key.size(), key) == 0) {
            std::size_t end = hdr.find(';', pos);
            return hdr.substr(pos + key.size(), end == std::string::npos ? std::string::npos : end - pos - key.size());
        }
        pos = hdr.find(';', pos);
        if (pos == std::string::npos) break;
    }
    return "";
}

struct StaticFile { const char* url; const char* relPath; const char* mime; };
const StaticFile kStaticFiles[] = {   // strict whitelist: no user-controlled file paths
    {"/", "index.html", "text/html; charset=utf-8"},
    {"/index.html", "index.html", "text/html; charset=utf-8"},
    {"/css/style.css", "css/style.css", "text/css; charset=utf-8"},
    {"/js/app.js", "js/app.js", "application/javascript; charset=utf-8"},
};

}  // namespace

struct ApiServer::Impl {
    explicit Impl(ServerConfig c) : cfg(std::move(c)), storage(cfg.vaultPath, cfg.kdf) { registerRoutes(); }

    ServerConfig cfg;
    httplib::Server svr;
    VaultStorage storage;
    PasswordManager manager;

    std::mutex mtx;                       // one request touches vault state at a time
    bool unlocked = false;
    std::string sessionToken;
    Clock::time_point lastActivity = Clock::now();
    bool dirty = false;                   // in-memory changes that failed to reach the disk
    int failedUnlocks = 0;
    Clock::time_point lockedUntil{};
    int boundPort = 0;
    std::vector<std::string> allowedHosts;

    // ---- session helpers (call with mtx held) ----
    bool persist() {
        std::string plain = manager.toJson();
        StorageStatus st = storage.save(plain);
        secureWipe(plain);
        dirty = (st != StorageStatus::Ok);
        return !dirty;
    }
    void lockVault() {
        storage.lock();
        manager.clear();
        secureWipe(sessionToken);
        unlocked = false;
        dirty = false;
    }
    void enforceIdle() {
        if (unlocked && Clock::now() - lastActivity > std::chrono::seconds(cfg.idleTimeoutSeconds)) {
            if (dirty) persist();
            lockVault();
        }
    }
    bool sessionValid(const Request& req) const {
        return unlocked && !sessionToken.empty() && constantTimeEquals(cookieValue(req, kCookieName), sessionToken);
    }
    void startSession(Response& res) {
        sessionToken = randomHex(32);
        unlocked = true;
        lastActivity = Clock::now();
        res.set_header("Set-Cookie", std::string(kCookieName) + "=" + sessionToken + "; Path=/; HttpOnly; SameSite=Strict");
    }
    void failStorage(Response& res, StorageStatus st, bool changeHeldInMemory) {
        std::string msg = statusMessage(st);
        if (changeHeldInMemory) msg += " Your change is kept in memory but is not saved to disk yet.";
        sendError(res, 500, "storage_error", msg);
    }

    template <class F>
    void guarded(const Request& req, Response& res, F fn) {
        std::lock_guard<std::mutex> lk(mtx);
        enforceIdle();
        if (!sessionValid(req)) { sendError(res, 401, "locked", "The vault is locked. Unlock it to continue."); return; }
        lastActivity = Clock::now();
        try { fn(); }
        catch (const std::exception&) { sendError(res, 500, "internal_error", "Unexpected server error."); }
    }

    bool hostAllowed(const Request& req) const {
        if (cfg.allowRemote) return true;
        const std::string h = toLowerAscii(req.get_header_value("Host"));
        for (const auto& a : allowedHosts) if (a == h) return true;
        return false;
    }

    // ---- route registration ----
    void registerRoutes() {
        svr.set_payload_max_length(64 * 1024);
        svr.set_read_timeout(10, 0);
        svr.set_write_timeout(10, 0);

        svr.set_pre_routing_handler([this](const Request& req, Response& res) {
            res.set_header("X-Content-Type-Options", "nosniff");
            res.set_header("X-Frame-Options", "DENY");
            res.set_header("Referrer-Policy", "no-referrer");
            res.set_header("Cache-Control", "no-store");
            res.set_header("Cross-Origin-Resource-Policy", "same-origin");
            res.set_header("Content-Security-Policy",
                           "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                           "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
            if (!hostAllowed(req)) {   // blocks DNS-rebinding attacks against the local server
                sendError(res, 403, "forbidden_host", "Requests must use http://127.0.0.1 or http://localhost.");
                return httplib::Server::HandlerResponse::Handled;
            }
            const bool api = req.path.rfind("/api/", 0) == 0;
            const bool changing = req.method != "GET" && req.method != "HEAD";
            if (api && changing) {     // CSRF defence: custom header + same-origin check
                if (req.get_header_value("X-Requested-With") != "ppm") {
                    sendError(res, 403, "csrf_blocked", "Missing X-Requested-With header.");
                    return httplib::Server::HandlerResponse::Handled;
                }
                if (req.has_header("Origin") &&
                    toLowerAscii(req.get_header_value("Origin")) != "http://" + toLowerAscii(req.get_header_value("Host"))) {
                    sendError(res, 403, "csrf_blocked", "Cross-origin requests are not allowed.");
                    return httplib::Server::HandlerResponse::Handled;
                }
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });

        svr.set_error_handler([](const Request& req, Response& res) {
            if (!res.body.empty()) return;
            if (req.path.rfind("/api/", 0) == 0) {
                std::string code = res.status == 404 ? "not_found" : res.status == 405 ? "method_not_allowed"
                                 : res.status == 413 ? "payload_too_large" : "http_error";
                sendError(res, res.status, code, "Request could not be processed (HTTP " + std::to_string(res.status) + ").");
            } else {
                res.set_content("Not found", "text/plain");
            }
        });

        svr.Get("/api/health", [](const Request&, Response& res) {
            sendJson(res, 200, {{"status", "ok"}, {"app", kAppTitle}, {"version", "1.0.0"}});
        });
        svr.Get("/api/categories", [](const Request&, Response& res) {
            sendJson(res, 200, {{"categories", PasswordManager::categories()}});
        });
        svr.Post("/api/generate-password", [this](const Request& req, Response& res) { handleGenerate(req, res); });

        svr.Get("/api/vault/status", [this](const Request& req, Response& res) { handleStatus(req, res); });
        svr.Post("/api/vault/init", [this](const Request& req, Response& res) { handleInit(req, res); });
        svr.Post("/api/vault/unlock", [this](const Request& req, Response& res) { handleUnlock(req, res); });
        svr.Post("/api/vault/lock", [this](const Request& req, Response& res) {
            guarded(req, res, [&] { handleLock(res); });
        });

        svr.Get("/api/accounts", [this](const Request& req, Response& res) { guarded(req, res, [&] { handleList(req, res); }); });
        svr.Get("/api/accounts/:id", [this](const Request& req, Response& res) { guarded(req, res, [&] { handleGet(req, res); }); });
        svr.Post("/api/accounts", [this](const Request& req, Response& res) { guarded(req, res, [&] { handleCreate(req, res); }); });
        svr.Put("/api/accounts/:id", [this](const Request& req, Response& res) { guarded(req, res, [&] { handleUpdate(req, res); }); });
        svr.Delete("/api/accounts/:id", [this](const Request& req, Response& res) { guarded(req, res, [&] { handleDelete(req, res); }); });
        svr.Post("/api/undo-delete", [this](const Request& req, Response& res) { guarded(req, res, [&] { handleUndo(res); }); });

        for (const StaticFile& f : kStaticFiles) {
            svr.Get(f.url, [this, f](const Request&, Response& res) {
                std::ifstream in(std::filesystem::path(cfg.frontendDir) / f.relPath, std::ios::binary);
                if (!in) { res.status = 404; res.set_content("Frontend file not found. Check --frontend.", "text/plain"); return; }
                std::ostringstream ss;
                ss << in.rdbuf();
                res.set_content(ss.str(), f.mime);
            });
        }
    }

    // ---- handlers ----
    void handleGenerate(const Request& req, Response& res) {
        json body;
        if (!readJsonObject(req, res, body)) return;
        GeneratorOptions o;
        auto readBool = [&](const char* key, bool& dst) {
            auto it = body.find(key);
            if (it == body.end()) return true;
            if (!it->is_boolean()) { sendError(res, 400, "validation_error", std::string(key) + " must be true or false.", key); return false; }
            dst = it->get<bool>();
            return true;
        };
        auto lenIt = body.find("length");
        if (lenIt != body.end()) {
            if (!lenIt->is_number_integer()) { sendError(res, 400, "validation_error", "length must be a whole number.", "length"); return; }
            long long v = lenIt->get<long long>();
            if (v < PasswordGenerator::kMinLength || v > PasswordGenerator::kMaxLength) {
                sendError(res, 400, "validation_error", PasswordGenerator::validate({static_cast<int>(v < 0 ? 0 : (v > 100000 ? 100000 : v)), true, true, true, true}), "length");
                return;
            }
            o.length = static_cast<int>(v);
        }
        if (!readBool("lowercase", o.lowercase) || !readBool("uppercase", o.uppercase) ||
            !readBool("numbers", o.numbers) || !readBool("symbols", o.symbols)) return;
        GeneratorResult r = PasswordGenerator::generate(o);
        if (!r.ok) { sendError(res, 400, "validation_error", r.error); return; }
        sendJson(res, 200, {{"password", r.password}, {"length", o.length}});
    }

    void handleStatus(const Request& req, Response& res) {
        std::lock_guard<std::mutex> lk(mtx);
        enforceIdle();   // note: status checks do NOT count as activity
        long long retry = 0;
        if (Clock::now() < lockedUntil)
            retry = std::chrono::duration_cast<std::chrono::seconds>(lockedUntil - Clock::now()).count() + 1;
        sendJson(res, 200, {{"initialized", storage.exists()}, {"unlocked", sessionValid(req)},
                            {"idleTimeoutSeconds", cfg.idleTimeoutSeconds}, {"retryAfterSeconds", retry}});
    }

    void handleInit(const Request& req, Response& res) {
        std::lock_guard<std::mutex> lk(mtx);
        json body;
        if (!readJsonObject(req, res, body)) return;
        std::optional<std::string> pw;
        if (!optString(body, "masterPassword", pw, res)) return;
        if (!pw) { sendError(res, 400, "validation_error", "masterPassword is required.", "masterPassword"); return; }
        if (storage.exists()) { sendError(res, 409, "vault_exists", "A vault already exists. Unlock it instead."); return; }
        std::size_t n = countCodePoints(*pw);
        if (n < 12 || n > 256) {
            sendError(res, 400, "validation_error", "Master password must be 12 to 256 characters.", "masterPassword");
            return;
        }
        manager.clear();
        std::string plain = manager.toJson();
        StorageStatus st = storage.create(*pw, plain);
        secureWipe(plain);
        if (st != StorageStatus::Ok) { failStorage(res, st, false); return; }
        startSession(res);
        sendJson(res, 201, {{"unlocked", true}});
    }

    void handleUnlock(const Request& req, Response& res) {
        std::lock_guard<std::mutex> lk(mtx);
        enforceIdle();
        json body;
        if (!readJsonObject(req, res, body)) return;
        std::optional<std::string> pw;
        if (!optString(body, "masterPassword", pw, res)) return;
        if (!pw || pw->empty() || pw->size() > 1024) {
            sendError(res, 400, "validation_error", "masterPassword is required.", "masterPassword");
            return;
        }
        if (!storage.exists()) { sendError(res, 404, "vault_missing", "No vault found. Create one first."); return; }
        if (Clock::now() < lockedUntil) {
            long long wait = std::chrono::duration_cast<std::chrono::seconds>(lockedUntil - Clock::now()).count() + 1;
            res.set_header("Retry-After", std::to_string(wait));
            sendError(res, 429, "too_many_attempts", "Too many failed attempts. Try again in " + std::to_string(wait) + " seconds.");
            return;
        }
        std::string plain;
        StorageStatus st = storage.unlock(*pw, plain);
        if (st != StorageStatus::Ok) {
            secureWipe(plain);
            if (st == StorageStatus::WrongPasswordOrCorrupt) {
                if (++failedUnlocks >= cfg.maxFailedUnlocks) {
                    failedUnlocks = 0;
                    lockedUntil = Clock::now() + std::chrono::seconds(cfg.lockoutSeconds);
                }
                sendError(res, 401, "invalid_credentials", statusMessage(st));
            } else if (st == StorageStatus::Corrupt || st == StorageStatus::UnsupportedVersion) {
                sendError(res, 422, "vault_corrupted", std::string(statusMessage(st)) + " The file was left untouched.");
            } else {
                sendError(res, 500, "storage_error", statusMessage(st));
            }
            return;
        }
        failedUnlocks = 0;
        if (!(unlocked && dirty)) {            // never discard unsaved in-memory changes
            OpResult lr = manager.loadJson(plain);
            if (!lr.ok()) {
                secureWipe(plain);
                storage.lock();
                sendError(res, 422, "vault_corrupted", "Vault decrypted but its contents are invalid. The file was left untouched.");
                return;
            }
        }
        secureWipe(plain);
        startSession(res);
        sendJson(res, 200, {{"unlocked", true}});
    }

    void handleLock(Response& res) {
        if (dirty && !persist()) { failStorage(res, StorageStatus::IoError, true); return; }
        lockVault();
        res.set_header("Set-Cookie", std::string(kCookieName) + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
        sendJson(res, 200, {{"unlocked", false}});
    }

    void handleList(const Request& req, Response& res) {
        std::string q = req.get_param_value("q");
        std::string cat = req.get_param_value("category");
        if (q.size() > 100) { sendError(res, 400, "validation_error", "Search text is too long.", "q"); return; }
        if (cat == "All") cat.clear();
        if (!cat.empty() && !PasswordManager::isValidCategory(cat)) {
            sendError(res, 400, "validation_error", "Unknown category.", "category");
            return;
        }
        json list = json::array();
        for (const auto& m : manager.search(q, cat)) list.push_back(metaToJson(m));
        sendJson(res, 200, {{"accounts", list}, {"count", list.size()}, {"stats", statsToJson(manager.stats(), dirty)}});
    }

    void handleGet(const Request& req, Response& res) {
        const PasswordEntry* e = manager.find(req.path_params.at("id"));
        if (!e) { sendError(res, 404, "not_found", "Account not found."); return; }
        json acc = metaToJson(manager.describe(*e));
        acc["password"] = e->password();   // the ONLY endpoint that returns a password
        sendJson(res, 200, {{"account", acc}});
    }

    void handleCreate(const Request& req, Response& res) {
        json body;
        if (!readJsonObject(req, res, body)) return;
        AccountInput in;
        if (!readAccountInput(body, in, res)) return;
        AccountMeta meta;
        OpResult r = manager.addAccount(in, meta);
        if (!r.ok()) { sendOpError(res, r); return; }
        if (!persist()) { failStorage(res, StorageStatus::IoError, true); return; }
        res.set_header("Location", "/api/accounts/" + meta.id);
        sendJson(res, 201, {{"account", metaToJson(meta)}});
    }

    void handleUpdate(const Request& req, Response& res) {
        json body;
        if (!readJsonObject(req, res, body)) return;
        AccountInput in;
        if (!readAccountInput(body, in, res)) return;
        AccountMeta meta;
        OpResult r = manager.updateAccount(req.path_params.at("id"), in, meta);
        if (!r.ok()) { sendOpError(res, r); return; }
        if (!persist()) { failStorage(res, StorageStatus::IoError, true); return; }
        sendJson(res, 200, {{"account", metaToJson(meta)}});
    }

    void handleDelete(const Request& req, Response& res) {
        AccountMeta meta;
        OpResult r = manager.deleteAccount(req.path_params.at("id"), meta);
        if (!r.ok()) { sendOpError(res, r); return; }
        if (!persist()) { failStorage(res, StorageStatus::IoError, true); return; }
        sendJson(res, 200, {{"deleted", metaToJson(meta)}, {"undoAvailable", true}, {"undoDepth", manager.undoDepth()}});
    }

    void handleUndo(Response& res) {
        AccountMeta meta;
        OpResult r = manager.undoDelete(meta);
        if (!r.ok()) { sendOpError(res, r); return; }
        if (!persist()) { failStorage(res, StorageStatus::IoError, true); return; }
        sendJson(res, 200, {{"restored", metaToJson(meta)}, {"undoDepth", manager.undoDepth()}});
    }
};

ApiServer::ApiServer(ServerConfig config) : impl_(new Impl(std::move(config))) {}
ApiServer::~ApiServer() = default;

bool ApiServer::bind() {
    Impl& s = *impl_;
    if (s.cfg.port == 0) {
        s.boundPort = s.svr.bind_to_any_port(s.cfg.host);
        if (s.boundPort < 0) { s.boundPort = 0; return false; }
    } else {
        if (!s.svr.bind_to_port(s.cfg.host, s.cfg.port)) return false;
        s.boundPort = s.cfg.port;
    }
    const std::string p = ":" + std::to_string(s.boundPort);
    s.allowedHosts = {"127.0.0.1" + p, "localhost" + p, "[::1]" + p, s.cfg.host + p};
    return true;
}

int ApiServer::port() const { return impl_->boundPort; }
void ApiServer::run() { impl_->svr.listen_after_bind(); }
void ApiServer::waitUntilReady() { impl_->svr.wait_until_ready(); }
void ApiServer::stop() { impl_->svr.stop(); }

}  // namespace ppm
