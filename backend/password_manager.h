// password_manager.h - account operations on top of LinkedList + UndoStack.
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "linked_list.h"
#include "password_entry.h"
#include "stack.h"

namespace ppm {

// What the API may show in list responses: everything EXCEPT the password.
struct AccountMeta {
    std::string id, website, username, category;
    std::int64_t createdAt = 0, updatedAt = 0;
    bool weak = false;     // password looks weak
    bool reused = false;   // same password used by another account
};

struct AccountInput {
    std::optional<std::string> website, username, password, category;
};

enum class ErrorCode { None, Validation, NotFound, NothingToUndo };

struct OpResult {
    ErrorCode code = ErrorCode::None;
    std::string field;     // which input field caused a validation error
    std::string message;
    bool ok() const { return code == ErrorCode::None; }
    static OpResult success() { return {}; }
    static OpResult failure(ErrorCode c, std::string msg, std::string field = "") {
        OpResult r; r.code = c; r.message = std::move(msg); r.field = std::move(field); return r;
    }
};

struct VaultStats {
    std::size_t total = 0, weak = 0, reused = 0, undoDepth = 0;
    std::vector<std::pair<std::string, std::size_t>> byCategory;
};

class PasswordManager {
public:
    PasswordManager() = default;

    static const std::vector<std::string>& categories();
    static bool isValidCategory(const std::string& c);
    static bool isWeakPassword(const std::string& pw);

    OpResult addAccount(const AccountInput& in, AccountMeta& created);
    OpResult updateAccount(const std::string& id, const AccountInput& in, AccountMeta& updated);
    OpResult deleteAccount(const std::string& id, AccountMeta& deleted);
    OpResult undoDelete(AccountMeta& restored);

    // Case-insensitive search of website/username; empty category = all categories.
    std::vector<AccountMeta> search(const std::string& query, const std::string& category) const;
    const PasswordEntry* find(const std::string& id) const { return list_.findById(id); }
    AccountMeta describe(const PasswordEntry& e) const;   // meta incl. weak/reused flags
    VaultStats stats() const;

    std::size_t size() const { return list_.size(); }
    std::size_t undoDepth() const { return undo_.size(); }

    // Serialisation of the vault payload (plaintext JSON - encrypt before storing!).
    std::string toJson() const;
    OpResult loadJson(const std::string& text);   // all-or-nothing; keeps old data on failure
    void clear();                                 // empties list and undo stack

private:
    static AccountMeta basicMeta(const PasswordEntry& e);
    std::string newUniqueId() const;

    LinkedList list_;
    UndoStack undo_;
};

}  // namespace ppm
