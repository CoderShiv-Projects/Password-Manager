// API tests: a real ApiServer on an ephemeral loopback port, driven by httplib::Client.
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <thread>

#include "api.h"
#include "crypto_util.h"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "test_framework.h"

using namespace ppm;
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

const char* kMaster = "fake-master-password-123";

struct TestServer {
    fs::path dir;
    std::unique_ptr<ApiServer> server;
    std::thread th;
    std::string cookie;

    explicit TestServer(const fs::path& existingDir = {}, int idleSeconds = 600) {
        dir = existingDir.empty() ? fs::temp_directory_path() / ("ppm_api_" + randomHex(6)) : existingDir;
        fs::create_directories(dir);
        ServerConfig cfg;
        cfg.port = 0;
        cfg.vaultPath = (dir / "vault.dat").string();
        cfg.frontendDir = (fs::path(PPM_SOURCE_DIR) / "frontend").string();
        cfg.kdf = KdfParams::testing();
        cfg.idleTimeoutSeconds = idleSeconds;
        server = std::make_unique<ApiServer>(cfg);
        if (!server->bind()) throw std::runtime_error("bind failed");
        th = std::thread([this] { server->run(); });
        server->waitUntilReady();
    }
    ~TestServer() { server->stop(); th.join(); }

    httplib::Headers headers(bool csrf = true, bool withCookie = true) const {
        httplib::Headers h;
        if (csrf) h.emplace("X-Requested-With", "ppm");
        if (withCookie && !cookie.empty()) h.emplace("Cookie", cookie);
        return h;
    }
    httplib::Client client() const { return httplib::Client("127.0.0.1", server->port()); }

    httplib::Result get(const std::string& path) { auto c = client(); return c.Get(path, headers()); }
    httplib::Result post(const std::string& path, const std::string& body = "{}") {
        auto c = client(); return c.Post(path, headers(), body, "application/json");
    }
    httplib::Result put(const std::string& path, const std::string& body) {
        auto c = client(); return c.Put(path, headers(), body, "application/json");
    }
    httplib::Result del(const std::string& path) { auto c = client(); return c.Delete(path, headers()); }

    bool initVault() {
        auto r = post("/api/vault/init", json{{"masterPassword", kMaster}}.dump());
        return capture(r) && r->status == 201;
    }
    bool unlock(const char* pw = kMaster) {
        auto r = post("/api/vault/unlock", json{{"masterPassword", pw}}.dump());
        return capture(r) && r->status == 200;
    }
    bool capture(const httplib::Result& r) {
        if (!r) return false;
        if (r->has_header("Set-Cookie")) {
            std::string sc = r->get_header_value("Set-Cookie");
            cookie = sc.substr(0, sc.find(';'));
        }
        return true;
    }
    std::string addAccount(const std::string& site, const std::string& user, const std::string& pw,
                           const std::string& cat = "Work") {
        auto r = post("/api/accounts", json{{"website", site}, {"username", user}, {"password", pw}, {"category", cat}}.dump());
        if (!r || r->status != 201) return "";
        return json::parse(r->body)["account"]["id"].get<std::string>();
    }
};

json body(const httplib::Result& r) { return json::parse(r->body, nullptr, false); }

}  // namespace

TEST(api_health_and_categories_need_no_session) {
    TestServer t;
    auto h = t.get("/api/health");
    CHECK(h && h->status == 200);
    CHECK_EQ(body(h)["status"].get<std::string>(), std::string("ok"));
    auto c = t.get("/api/categories");
    CHECK(c && c->status == 200);
    CHECK_EQ(body(c)["categories"].size(), std::size_t(7));
}

TEST(api_protected_routes_require_unlocked_session) {
    TestServer t;
    CHECK(t.get("/api/accounts")->status == 401);
    CHECK(t.get("/api/accounts/abc")->status == 401);
    CHECK(t.post("/api/accounts")->status == 401);
    CHECK(t.post("/api/undo-delete")->status == 401);
    CHECK(t.del("/api/accounts/abc")->status == 401);
    t.initVault();
    CHECK(t.get("/api/accounts")->status == 200);
    t.cookie = "ppm_session=forged";                       // wrong token
    CHECK(t.get("/api/accounts")->status == 401);
}

TEST(api_vault_init_validation_and_double_init) {
    TestServer t;
    auto st = body(t.get("/api/vault/status"));
    CHECK(!st["initialized"].get<bool>());
    CHECK(t.post("/api/vault/init", json{{"masterPassword", "short"}}.dump())->status == 400);
    CHECK(t.post("/api/vault/init", json{{"masterPassword", 12345}}.dump())->status == 400);
    CHECK(t.post("/api/vault/init", "{}")->status == 400);
    CHECK(t.initVault());
    CHECK(t.post("/api/vault/init", json{{"masterPassword", kMaster}}.dump())->status == 409);
    CHECK(body(t.get("/api/vault/status"))["unlocked"].get<bool>());
}

TEST(api_csrf_and_host_protection) {
    TestServer t;
    t.initVault();
    auto c = t.client();
    auto noHeader = c.Post("/api/undo-delete", t.headers(false), "{}", "application/json");
    CHECK(noHeader && noHeader->status == 403);
    httplib::Headers evil = t.headers();
    evil.emplace("Origin", "http://evil.example");
    auto crossOrigin = c.Post("/api/undo-delete", evil, "{}", "application/json");
    CHECK(crossOrigin && crossOrigin->status == 403);
    httplib::Headers rebinding = t.headers();
    rebinding.emplace("Host", "evil.example");
    auto badHost = c.Get("/api/health", rebinding);
    CHECK(badHost && badHost->status == 403);
    httplib::Headers sameOrigin = t.headers();
    sameOrigin.emplace("Origin", "http://127.0.0.1:" + std::to_string(t.server->port()));
    auto ok = c.Post("/api/undo-delete", sameOrigin, "{}", "application/json");
    CHECK(ok && ok->status == 409);                        // allowed through; nothing to undo
}

TEST(api_security_headers_present) {
    TestServer t;
    auto r = t.get("/api/health");
    CHECK(r->has_header("Content-Security-Policy"));
    CHECK_EQ(r->get_header_value("X-Content-Type-Options"), std::string("nosniff"));
    CHECK_EQ(r->get_header_value("Cache-Control"), std::string("no-store"));
}

TEST(api_create_list_and_get_account_without_leaking_password) {
    TestServer t; t.initVault();
    std::string id = t.addAccount("example.test", "alice@example.test", "FAKE-pw-Abc123!xyz");
    CHECK(!id.empty());
    auto list = t.get("/api/accounts");
    CHECK(list && list->status == 200);
    CHECK(list->body.find("FAKE-pw-Abc123!xyz") == std::string::npos);   // never in the list
    CHECK(list->body.find("\"password\"") == std::string::npos);
    CHECK_EQ(body(list)["count"].get<int>(), 1);
    CHECK_EQ(body(list)["stats"]["total"].get<int>(), 1);
    auto one = t.get("/api/accounts/" + id);
    CHECK(one && one->status == 200);
    CHECK_EQ(body(one)["account"]["password"].get<std::string>(), std::string("FAKE-pw-Abc123!xyz"));
    CHECK(t.get("/api/accounts/doesnotexist")->status == 404);
}

TEST(api_invalid_requests_get_proper_errors) {
    TestServer t; t.initVault();
    CHECK(t.post("/api/accounts", "{not json")->status == 400);
    CHECK(t.post("/api/accounts", "[]")->status == 400);
    CHECK(t.post("/api/accounts", "")->status == 400);
    CHECK(t.post("/api/accounts", "{\"website\":\"x\"}")->status == 400);
    auto badType = t.post("/api/accounts", "{\"website\":5,\"username\":\"u\",\"password\":\"p\",\"category\":\"Work\"}");
    CHECK(badType->status == 400);
    CHECK_EQ(body(badType)["error"]["field"].get<std::string>(), std::string("website"));
    CHECK(t.post("/api/accounts", "{\"website\":\"x\",\"username\":\"u\",\"password\":\"p\",\"category\":\"Nope\"}")->status == 400);
    auto c = t.client();
    auto wrongType = c.Post("/api/accounts", t.headers(), "website=x", "application/x-www-form-urlencoded");
    CHECK(wrongType && wrongType->status == 415);
    auto huge = c.Post("/api/accounts", t.headers(), std::string(70 * 1024, 'a'), "application/json");
    CHECK(huge && huge->status == 413);
    CHECK(t.get("/api/accounts?category=Nope")->status == 400);
    CHECK(t.get("/api/nothing")->status == 404);
    auto wrongMethod = t.put("/api/accounts", "{}");
    CHECK(wrongMethod && wrongMethod->status >= 400);
    CHECK_EQ(body(t.get("/api/accounts"))["count"].get<int>(), 0);   // nothing was stored
}

TEST(api_search_filter_and_duplicates) {
    TestServer t; t.initVault();
    t.addAccount("GitHub", "dev@example.test", "Fake-Pass-1!", "Development");
    t.addAccount("GitHub", "dev@example.test", "Fake-Pass-2!", "Development");   // duplicate site + user allowed
    t.addAccount("Bank", "me@example.test", "Fake-Pass-3!", "Finance");
    CHECK_EQ(body(t.get("/api/accounts"))["count"].get<int>(), 3);
    CHECK_EQ(body(t.get("/api/accounts?q=github"))["count"].get<int>(), 2);
    CHECK_EQ(body(t.get("/api/accounts?q=me@"))["count"].get<int>(), 1);
    CHECK_EQ(body(t.get("/api/accounts?category=Finance"))["count"].get<int>(), 1);
    CHECK_EQ(body(t.get("/api/accounts?q=github&category=Finance"))["count"].get<int>(), 0);
    auto all = body(t.get("/api/accounts"))["accounts"];
    CHECK(all[0]["id"].get<std::string>() != all[1]["id"].get<std::string>());
}

TEST(api_update_account) {
    TestServer t; t.initVault();
    std::string id = t.addAccount("old.test", "u", "Fake-Pass-1!");
    auto r = t.put("/api/accounts/" + id, "{\"website\":\"new.test\",\"category\":\"Shopping\"}");
    CHECK(r && r->status == 200);
    CHECK_EQ(body(r)["account"]["website"].get<std::string>(), std::string("new.test"));
    CHECK_EQ(body(t.get("/api/accounts/" + id))["account"]["password"].get<std::string>(), std::string("Fake-Pass-1!"));
    CHECK(t.put("/api/accounts/" + id, "{\"password\":\"New-Fake-Pass-2!\"}")->status == 200);
    CHECK_EQ(body(t.get("/api/accounts/" + id))["account"]["password"].get<std::string>(), std::string("New-Fake-Pass-2!"));
    CHECK(t.put("/api/accounts/" + id, "{}")->status == 400);
    CHECK(t.put("/api/accounts/" + id, "{\"category\":\"Nope\"}")->status == 400);
    CHECK(t.put("/api/accounts/missing", "{\"website\":\"x\"}")->status == 404);
}

TEST(api_delete_and_undo_delete) {
    TestServer t; t.initVault();
    CHECK(t.post("/api/undo-delete")->status == 409);      // empty stack handled gracefully
    std::string a = t.addAccount("a.test", "u", "Fake-Pass-1!");
    std::string b = t.addAccount("b.test", "u", "Fake-Pass-2!");
    auto d = t.del("/api/accounts/" + a);
    CHECK(d && d->status == 200);
    CHECK(body(d)["undoAvailable"].get<bool>());
    CHECK(t.del("/api/accounts/" + a)->status == 404);
    CHECK(t.del("/api/accounts/" + b)->status == 200);
    CHECK_EQ(body(t.get("/api/accounts"))["count"].get<int>(), 0);
    auto u1 = t.post("/api/undo-delete");
    CHECK(u1 && u1->status == 200);
    CHECK_EQ(body(u1)["restored"]["id"].get<std::string>(), b);   // most recent deletion first
    CHECK(t.post("/api/undo-delete")->status == 200);
    CHECK(t.post("/api/undo-delete")->status == 409);
    CHECK_EQ(body(t.get("/api/accounts"))["count"].get<int>(), 2);
    CHECK_EQ(body(t.get("/api/accounts/" + a))["account"]["password"].get<std::string>(), std::string("Fake-Pass-1!"));
}

TEST(api_data_survives_restart_and_lock_unlock) {
    fs::path dir = fs::temp_directory_path() / ("ppm_api_" + randomHex(6));
    std::string id;
    {
        TestServer t(dir); t.initVault();
        id = t.addAccount("persist.test", "u", "Fake-Pass-1!", "Education");
        auto lockRes = t.post("/api/vault/lock");
        CHECK(lockRes && lockRes->status == 200);
        CHECK(t.get("/api/accounts")->status == 401);       // locked
    }
    {
        TestServer t(dir);                                   // "restart": brand-new server, same vault file
        CHECK(body(t.get("/api/vault/status"))["initialized"].get<bool>());
        CHECK(t.get("/api/accounts")->status == 401);
        CHECK(t.unlock());
        auto one = t.get("/api/accounts/" + id);
        CHECK(one && one->status == 200);
        CHECK_EQ(body(one)["account"]["website"].get<std::string>(), std::string("persist.test"));
        CHECK(t.post("/api/undo-delete")->status == 409);    // undo history does not survive a restart
    }
    std::error_code ec; fs::remove_all(dir, ec);
}

TEST(api_wrong_master_password_and_lockout) {
    TestServer t; t.initVault();
    t.post("/api/vault/lock");
    auto bad = t.post("/api/vault/unlock", json{{"masterPassword", "wrong-password-123"}}.dump());
    CHECK(bad && bad->status == 401);
    CHECK_EQ(body(bad)["error"]["code"].get<std::string>(), std::string("invalid_credentials"));
    CHECK(t.get("/api/accounts")->status == 401);
    CHECK(t.post("/api/vault/unlock", "{}")->status == 400);
    for (int i = 0; i < 4; ++i) t.post("/api/vault/unlock", json{{"masterPassword", "wrong-password-123"}}.dump());
    auto locked = t.post("/api/vault/unlock", json{{"masterPassword", kMaster}}.dump());
    CHECK(locked && locked->status == 429);                  // lock-out engaged even for the right password
    CHECK(locked->has_header("Retry-After"));
}

TEST(api_corrupted_vault_is_reported_and_never_overwritten) {
    fs::path dir = fs::temp_directory_path() / ("ppm_api_" + randomHex(6));
    {
        TestServer t(dir); t.initVault();
        t.addAccount("a.test", "u", "Fake-Pass-1!");
    }
    auto readAll = [&] { std::ifstream in(dir / "vault.dat", std::ios::binary); return std::string(std::istreambuf_iterator<char>(in), {}); };
    std::string good = readAll();
    {   // truncated file -> 422 vault_corrupted
        std::string cut = good.substr(0, 40);
        std::ofstream(dir / "vault.dat", std::ios::binary | std::ios::trunc) << cut;
        TestServer t(dir);
        auto r = t.post("/api/vault/unlock", json{{"masterPassword", kMaster}}.dump());
        CHECK(r && r->status == 422);
        CHECK_EQ(body(r)["error"]["code"].get<std::string>(), std::string("vault_corrupted"));
        CHECK(t.post("/api/vault/init", json{{"masterPassword", kMaster}}.dump())->status == 409);  // init cannot overwrite it
        CHECK_EQ(readAll(), cut);
    }
    {   // flipped ciphertext bit -> authentication failure, file untouched
        std::string flipped = good; flipped[flipped.size() - 5] ^= 0x01;
        std::ofstream(dir / "vault.dat", std::ios::binary | std::ios::trunc) << flipped;
        TestServer t(dir);
        auto r = t.post("/api/vault/unlock", json{{"masterPassword", kMaster}}.dump());
        CHECK(r && r->status == 401);
        CHECK_EQ(readAll(), flipped);
    }
    std::error_code ec; fs::remove_all(dir, ec);
}

TEST(api_generate_password_endpoint) {
    TestServer t;
    auto ok = t.post("/api/generate-password", "{\"length\":20,\"lowercase\":true,\"uppercase\":true,\"numbers\":true,\"symbols\":false}");
    CHECK(ok && ok->status == 200);
    CHECK_EQ(body(ok)["password"].get<std::string>().size(), std::size_t(20));
    CHECK(body(ok)["password"].get<std::string>().find_first_of("!@#$%^&*()-_=+[]{};:,.?/~") == std::string::npos);
    CHECK(t.post("/api/generate-password", "{}")->status == 200);                       // defaults
    CHECK(t.post("/api/generate-password", "{\"length\":4}")->status == 400);
    CHECK(t.post("/api/generate-password", "{\"length\":\"ten\"}")->status == 400);
    CHECK(t.post("/api/generate-password", "{\"length\":12.5}")->status == 400);
    CHECK(t.post("/api/generate-password", "{\"length\":999999999999}")->status == 400);
    CHECK(t.post("/api/generate-password", "{\"lowercase\":false,\"uppercase\":false,\"numbers\":false,\"symbols\":false}")->status == 400);
    CHECK(t.post("/api/generate-password", "{\"symbols\":\"yes\"}")->status == 400);
}

TEST(api_idle_timeout_locks_vault) {
    TestServer t(fs::path{}, 1);
    t.initVault();
    CHECK(t.get("/api/accounts")->status == 200);
    std::this_thread::sleep_for(std::chrono::milliseconds(1300));
    CHECK(t.get("/api/accounts")->status == 401);
}

TEST(api_static_files_whitelisted_and_no_traversal) {
    TestServer t;
    auto idx = t.get("/");
    CHECK(idx && idx->status == 200);
    CHECK(idx->body.find("Personal Password Management and Account Credential Organization System") != std::string::npos);
    CHECK(t.get("/css/style.css")->status == 200);
    CHECK(t.get("/js/app.js")->status == 200);
    CHECK(t.get("/../CMakeLists.txt")->status == 404);
    CHECK(t.get("/js/../../CMakeLists.txt")->status == 404);
    CHECK(t.get("/..%2FCMakeLists.txt")->status == 404);
    CHECK(t.get("/index.html/../../README.md")->status == 404);
    CHECK(t.get("/CMakeLists.txt")->status == 404);
    CHECK(t.get("/data/vault.dat")->status == 404);
}
