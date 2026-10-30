// password_entry.h - the account record stored in every linked-list node.
#pragma once
#include <cstdint>
#include <string>

namespace ppm {

// ---- small string / time helpers shared across the backend -----------------
std::int64_t unixNow();                               // seconds since 1970-01-01 UTC
std::string formatIso8601(std::int64_t epochSeconds); // "2026-10-30T12:00:00Z"
std::string toLowerAscii(const std::string& s);       // ASCII-only lower-casing
std::string trimCopy(const std::string& s);           // strips leading/trailing whitespace

// One saved account. The password is wiped from memory when the entry dies
// (best effort: copies made by the C++ runtime elsewhere cannot be tracked).
class PasswordEntry {
public:
    PasswordEntry() = default;
    PasswordEntry(std::string id, std::string website, std::string username,
                  std::string password, std::string category,
                  std::int64_t createdAt, std::int64_t updatedAt);

    PasswordEntry(const PasswordEntry& other);
    PasswordEntry(PasswordEntry&& other) noexcept;
    PasswordEntry& operator=(const PasswordEntry& other);
    PasswordEntry& operator=(PasswordEntry&& other) noexcept;
    ~PasswordEntry();

    const std::string& id() const { return id_; }
    const std::string& website() const { return website_; }
    const std::string& username() const { return username_; }
    const std::string& password() const { return password_; }
    const std::string& category() const { return category_; }
    std::int64_t createdAt() const { return createdAt_; }
    std::int64_t updatedAt() const { return updatedAt_; }

    void setWebsite(std::string v) { website_ = std::move(v); }
    void setUsername(std::string v) { username_ = std::move(v); }
    void setPassword(std::string v);
    void setCategory(std::string v) { category_ = std::move(v); }
    void touch(std::int64_t now) { updatedAt_ = now; }

    // True when the lower-cased query occurs in the website or the username.
    bool matches(const std::string& lowerQuery) const;

private:
    std::string id_;
    std::string website_;
    std::string username_;
    std::string password_;
    std::string category_;
    std::int64_t createdAt_ = 0;
    std::int64_t updatedAt_ = 0;
};

}  // namespace ppm
