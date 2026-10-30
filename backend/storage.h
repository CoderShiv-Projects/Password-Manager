// storage.h - encrypted vault file (libsodium Argon2id + XChaCha20-Poly1305).
//
// File layout (all integers little-endian):
//   0..3    magic "PPMV"
//   4       format version (1)
//   5..12   Argon2id opslimit (u64)
//   13..20  Argon2id memlimit in bytes (u64)
//   21..36  random salt (16 bytes)
//   37..60  random nonce (24 bytes, fresh for every save)
//   61..    ciphertext + 16-byte Poly1305 tag
// Bytes 0..36 are authenticated as "additional data", so tampering with the
// header (e.g. weakening the KDF parameters) makes decryption fail.
#pragma once
#include <cstddef>
#include <memory>
#include <string>

namespace ppm {

struct KdfParams {
    unsigned long long opslimit;
    std::size_t memlimit;
    static KdfParams interactive();   // ~64 MiB, quick - for low-memory machines
    static KdfParams moderate();      // ~256 MiB, about a second - default
    static KdfParams testing();       // smallest legal values - ONLY for unit tests
};

enum class StorageStatus {
    Ok,
    NotFound,
    AlreadyExists,
    NotUnlocked,
    WrongPasswordOrCorrupt,   // authentication failed: wrong password OR modified ciphertext
    Corrupt,                  // header damaged / file truncated / bad magic
    UnsupportedVersion,
    KdfFailed,
    IoError
};

const char* statusMessage(StorageStatus s);

class VaultStorage {
public:
    VaultStorage(std::string path, KdfParams params);
    ~VaultStorage();
    VaultStorage(const VaultStorage&) = delete;
    VaultStorage& operator=(const VaultStorage&) = delete;

    bool exists() const;
    bool isUnlocked() const { return static_cast<bool>(key_); }

    // Creates a NEW vault file (refuses to overwrite an existing one) and unlocks it.
    StorageStatus create(const std::string& masterPassword, const std::string& plaintext);
    // Verifies the password, decrypts into `plaintextOut`, keeps the key in memory.
    // A failed attempt never modifies the file or the current unlocked state.
    StorageStatus unlock(const std::string& masterPassword, std::string& plaintextOut);
    // Re-encrypts with a fresh nonce and replaces the file atomically (temp file + rename).
    StorageStatus save(const std::string& plaintext);
    void lock();   // wipes the derived key from memory

private:
    struct KeyDeleter { void operator()(unsigned char* p) const; };
    using KeyPtr = std::unique_ptr<unsigned char, KeyDeleter>;

    StorageStatus writeFile(const std::string& plaintext);

    std::string path_;
    KdfParams params_;
    unsigned char salt_[16];
    KeyPtr key_;   // sodium_malloc'd (guarded, locked) 32-byte key
};

}  // namespace ppm
