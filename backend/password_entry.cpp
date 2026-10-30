#include "password_entry.h"

#include <cctype>
#include <chrono>
#include <ctime>
#include <utility>

#include "crypto_util.h"

namespace ppm {

std::int64_t unixNow() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::string formatIso8601(std::int64_t epochSeconds) {
    std::time_t t = static_cast<std::time_t>(epochSeconds);
    std::tm tmv{};
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

std::string toLowerAscii(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x80) c = static_cast<char>(std::tolower(u));
    }
    return out;
}

std::string trimCopy(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

PasswordEntry::PasswordEntry(std::string id, std::string website, std::string username,
                             std::string password, std::string category,
                             std::int64_t createdAt, std::int64_t updatedAt)
    : id_(std::move(id)), website_(std::move(website)), username_(std::move(username)),
      password_(std::move(password)), category_(std::move(category)),
      createdAt_(createdAt), updatedAt_(updatedAt) {}

PasswordEntry::PasswordEntry(const PasswordEntry& o)
    : id_(o.id_), website_(o.website_), username_(o.username_), password_(o.password_),
      category_(o.category_), createdAt_(o.createdAt_), updatedAt_(o.updatedAt_) {}

// "Move" = copy the password, then wipe the source, so no stale plaintext is
// left behind in the moved-from object (std::string move would not zero it).
PasswordEntry::PasswordEntry(PasswordEntry&& o) noexcept
    : id_(std::move(o.id_)), website_(std::move(o.website_)), username_(std::move(o.username_)),
      password_(o.password_), category_(std::move(o.category_)),
      createdAt_(o.createdAt_), updatedAt_(o.updatedAt_) {
    secureWipe(o.password_);
}

PasswordEntry& PasswordEntry::operator=(const PasswordEntry& o) {
    if (this != &o) {
        id_ = o.id_;
        website_ = o.website_;
        username_ = o.username_;
        secureWipe(password_);
        password_ = o.password_;
        category_ = o.category_;
        createdAt_ = o.createdAt_;
        updatedAt_ = o.updatedAt_;
    }
    return *this;
}

PasswordEntry& PasswordEntry::operator=(PasswordEntry&& o) noexcept {
    if (this != &o) {
        id_ = std::move(o.id_);
        website_ = std::move(o.website_);
        username_ = std::move(o.username_);
        secureWipe(password_);
        password_ = o.password_;
        secureWipe(o.password_);
        category_ = std::move(o.category_);
        createdAt_ = o.createdAt_;
        updatedAt_ = o.updatedAt_;
    }
    return *this;
}

PasswordEntry::~PasswordEntry() { secureWipe(password_); }

void PasswordEntry::setPassword(std::string v) {
    secureWipe(password_);
    password_ = std::move(v);
}

bool PasswordEntry::matches(const std::string& lowerQuery) const {
    if (lowerQuery.empty()) return true;
    return toLowerAscii(website_).find(lowerQuery) != std::string::npos ||
           toLowerAscii(username_).find(lowerQuery) != std::string::npos;
}

}  // namespace ppm
