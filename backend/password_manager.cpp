#include "password_manager.h"

#include <sodium.h>

#include <set>
#include <unordered_map>

#include "crypto_util.h"
#include "nlohmann/json.hpp"

namespace ppm {

using json = nlohmann::json;

namespace {

constexpr std::size_t kMaxWebsite = 100, kMaxUsername = 254, kMaxPassword = 256;

bool hasControlChars(const std::string& s) {
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f) return true;
    return false;
}

OpResult bad(const std::string& field, const std::string& msg) {
    return OpResult::failure(ErrorCode::Validation, msg, field);
}

// Each validator receives the raw value and returns the cleaned value via `out`.
OpResult checkWebsite(const std::string& raw, std::string& out) {
    out = trimCopy(raw);
    if (out.empty()) return bad("website", "Website or app name is required.");
    if (out.size() > kMaxWebsite) return bad("website", "Website must be at most 100 characters.");
    if (hasControlChars(out)) return bad("website", "Website contains invalid characters.");
    return OpResult::success();
}
OpResult checkUsername(const std::string& raw, std::string& out) {
    out = trimCopy(raw);
    if (out.empty()) return bad("username", "Username or email is required.");
    if (out.size() > kMaxUsername) return bad("username", "Username must be at most 254 characters.");
    if (hasControlChars(out)) return bad("username", "Username contains invalid characters.");
    return OpResult::success();
}
OpResult checkPassword(const std::string& raw) {
    if (raw.empty()) return bad("password", "Password is required.");
    if (raw.size() > kMaxPassword) return bad("password", "Password must be at most 256 characters.");
    if (hasControlChars(raw)) return bad("password", "Password contains invalid characters.");
    return OpResult::success();
}
OpResult checkCategory(const std::string& raw) {
    if (!PasswordManager::isValidCategory(raw))
        return bad("category", "Choose one of the predefined categories.");
    return OpResult::success();
}

// 16-byte BLAKE2b fingerprint so reuse detection never copies plaintext passwords around.
std::string fingerprint(const std::string& pw) {
    unsigned char h[16];
    crypto_generichash(h, sizeof h, reinterpret_cast<const unsigned char*>(pw.data()), pw.size(), nullptr, 0);
    return std::string(reinterpret_cast<char*>(h), sizeof h);
}

}  // namespace

const std::vector<std::string>& PasswordManager::categories() {
    static const std::vector<std::string> c = {"Social", "Work", "Education", "Finance",
                                               "Development", "Shopping", "Other"};
    return c;
}

bool PasswordManager::isValidCategory(const std::string& c) {
    for (const auto& k : categories())
        if (k == c) return true;
    return false;
}

bool PasswordManager::isWeakPassword(const std::string& pw) {
    bool lower = false, upper = false, digit = false, other = false;
    for (unsigned char c : pw) {
        if (c >= 'a' && c <= 'z') lower = true;
        else if (c >= 'A' && c <= 'Z') upper = true;
        else if (c >= '0' && c <= '9') digit = true;
        else other = true;
    }
    int classes = int(lower) + int(upper) + int(digit) + int(other);
    return pw.size() < 10 || classes < 3;
}

AccountMeta PasswordManager::basicMeta(const PasswordEntry& e) {
    AccountMeta m;
    m.id = e.id(); m.website = e.website(); m.username = e.username(); m.category = e.category();
    m.createdAt = e.createdAt(); m.updatedAt = e.updatedAt();
    return m;
}

AccountMeta PasswordManager::describe(const PasswordEntry& e) const {
    AccountMeta m = basicMeta(e);
    m.weak = isWeakPassword(e.password());
    const std::string fp = fingerprint(e.password());
    int same = 0;
    list_.forEach([&](const PasswordEntry& o) { if (fingerprint(o.password()) == fp) ++same; });
    m.reused = same > 1;
    return m;
}

std::string PasswordManager::newUniqueId() const {
    std::string id;
    do { id = randomHex(16); } while (list_.findById(id) != nullptr);
    return id;
}

OpResult PasswordManager::addAccount(const AccountInput& in, AccountMeta& created) {
    if (!in.website) return bad("website", "Website or app name is required.");
    if (!in.username) return bad("username", "Username or email is required.");
    if (!in.password) return bad("password", "Password is required.");
    if (!in.category) return bad("category", "Category is required.");

    std::string website, username;
    OpResult r;
    if (!(r = checkWebsite(*in.website, website)).ok()) return r;
    if (!(r = checkUsername(*in.username, username)).ok()) return r;
    if (!(r = checkPassword(*in.password)).ok()) return r;
    if (!(r = checkCategory(*in.category)).ok()) return r;

    const std::int64_t now = unixNow();
    const std::string id = newUniqueId();
    list_.pushBack(PasswordEntry(id, website, username, *in.password, *in.category, now, now));
    created = describe(*list_.findById(id));
    return OpResult::success();
}

OpResult PasswordManager::updateAccount(const std::string& id, const AccountInput& in, AccountMeta& updated) {
    PasswordEntry* e = list_.findById(id);
    if (!e) return OpResult::failure(ErrorCode::NotFound, "Account not found.");
    if (!in.website && !in.username && !in.password && !in.category)
        return bad("body", "Provide at least one field to update.");

    // Validate everything first so a bad field never causes a half-applied edit.
    std::string website, username;
    OpResult r;
    if (in.website && !(r = checkWebsite(*in.website, website)).ok()) return r;
    if (in.username && !(r = checkUsername(*in.username, username)).ok()) return r;
    if (in.password && !(r = checkPassword(*in.password)).ok()) return r;
    if (in.category && !(r = checkCategory(*in.category)).ok()) return r;

    if (in.website) e->setWebsite(website);
    if (in.username) e->setUsername(username);
    if (in.password) e->setPassword(*in.password);
    if (in.category) e->setCategory(*in.category);
    e->touch(unixNow());
    updated = describe(*e);
    return OpResult::success();
}

OpResult PasswordManager::deleteAccount(const std::string& id, AccountMeta& deleted) {
    DeletedRecord rec;
    if (!list_.removeById(id, &rec.entry, &rec.originalIndex))
        return OpResult::failure(ErrorCode::NotFound, "Account not found.");
    deleted = basicMeta(rec.entry);
    undo_.push(std::move(rec));
    return OpResult::success();
}

OpResult PasswordManager::undoDelete(AccountMeta& restored) {
    DeletedRecord rec;
    if (!undo_.pop(rec))
        return OpResult::failure(ErrorCode::NothingToUndo, "There is no deleted account to restore.");
    std::size_t idx = rec.originalIndex <= list_.size() ? rec.originalIndex : list_.size();
    const std::string id = rec.entry.id();
    list_.insertAt(idx, std::move(rec.entry));     // ownership moves back into the list
    restored = describe(*list_.findById(id));
    return OpResult::success();
}

std::vector<AccountMeta> PasswordManager::search(const std::string& query, const std::string& category) const {
    const std::string q = toLowerAscii(trimCopy(query));
    std::unordered_map<std::string, int> counts;       // fingerprint -> how many accounts use it
    list_.forEach([&](const PasswordEntry& e) { ++counts[fingerprint(e.password())]; });

    std::vector<AccountMeta> out;
    for (const LinkedList::Node* n = list_.head(); n; n = n->next) {
        const PasswordEntry& e = n->data;
        if (!category.empty() && e.category() != category) continue;
        if (!e.matches(q)) continue;
        AccountMeta m = basicMeta(e);
        m.weak = isWeakPassword(e.password());
        m.reused = counts[fingerprint(e.password())] > 1;
        out.push_back(std::move(m));
    }
    return out;
}

VaultStats PasswordManager::stats() const {
    VaultStats s;
    std::unordered_map<std::string, int> counts;
    list_.forEach([&](const PasswordEntry& e) { ++counts[fingerprint(e.password())]; });
    std::unordered_map<std::string, std::size_t> perCat;
    list_.forEach([&](const PasswordEntry& e) {
        ++s.total;
        ++perCat[e.category()];
        if (isWeakPassword(e.password())) ++s.weak;
        if (counts[fingerprint(e.password())] > 1) ++s.reused;
    });
    for (const auto& c : categories()) s.byCategory.emplace_back(c, perCat[c]);
    s.undoDepth = undo_.size();
    return s;
}

std::string PasswordManager::toJson() const {
    json entries = json::array();
    list_.forEach([&](const PasswordEntry& e) {
        entries.push_back({{"id", e.id()}, {"website", e.website()}, {"username", e.username()},
                           {"password", e.password()}, {"category", e.category()},
                           {"createdAt", e.createdAt()}, {"updatedAt", e.updatedAt()}});
    });
    json doc = {{"version", 1}, {"entries", entries}};
    return doc.dump(-1, ' ', false, json::error_handler_t::replace);
}

OpResult PasswordManager::loadJson(const std::string& text) {
    const OpResult badFormat = bad("vault", "Vault contents are not in a supported format.");
    json doc = json::parse(text, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) return badFormat;
    auto v = doc.find("version");
    auto en = doc.find("entries");
    if (v == doc.end() || !v->is_number_integer() || v->get<int>() != 1) return badFormat;
    if (en == doc.end() || !en->is_array()) return badFormat;

    LinkedList fresh;                         // build aside; swap in only if everything is valid
    std::set<std::string> ids;
    for (const json& j : *en) {
        if (!j.is_object()) return badFormat;
        for (const char* k : {"id", "website", "username", "password", "category"})
            if (!j.contains(k) || !j[k].is_string()) return badFormat;
        std::string id = j["id"].get<std::string>(), w, u;
        if (id.empty() || id.size() > 64 || hasControlChars(id) || !ids.insert(id).second) return badFormat;
        const std::string pw = j["password"].get<std::string>();
        if (!checkWebsite(j["website"].get<std::string>(), w).ok() ||
            !checkUsername(j["username"].get<std::string>(), u).ok() ||
            !checkPassword(pw).ok() || !checkCategory(j["category"].get<std::string>()).ok())
            return badFormat;
        std::int64_t c = j.value("createdAt", std::int64_t{0}), up = j.value("updatedAt", std::int64_t{0});
        fresh.pushBack(PasswordEntry(id, w, u, pw, j["category"].get<std::string>(), c, up));
    }
    list_ = std::move(fresh);
    undo_.clear();
    return OpResult::success();
}

void PasswordManager::clear() {
    list_.clear();
    undo_.clear();
}

}  // namespace ppm
