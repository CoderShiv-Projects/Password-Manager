#include "storage.h"

#include <sodium.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

#include "crypto_util.h"

namespace fs = std::filesystem;

namespace ppm {

namespace {
constexpr unsigned char kMagic[4] = {'P', 'P', 'M', 'V'};
constexpr unsigned char kVersion = 1;
constexpr std::size_t kSaltLen = crypto_pwhash_SALTBYTES;                           // 16
constexpr std::size_t kNonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;     // 24
constexpr std::size_t kKeyLen = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;        // 32
constexpr std::size_t kTagLen = crypto_aead_xchacha20poly1305_ietf_ABYTES;          // 16
constexpr std::size_t kAdLen = 4 + 1 + 8 + 8 + kSaltLen;                            // 37
constexpr std::size_t kHeaderLen = kAdLen + kNonceLen;                              // 61
constexpr std::uintmax_t kMaxFileSize = 64ull * 1024 * 1024;
constexpr unsigned long long kMaxOps = 20;
constexpr unsigned long long kMaxMem = 1ull << 30;   // refuse absurd values from a tampered file

void putU64(unsigned char* p, std::uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = static_cast<unsigned char>(v >> (8 * i)); }
std::uint64_t getU64(const unsigned char* p) { std::uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= std::uint64_t(p[i]) << (8 * i); return v; }

}  // namespace

KdfParams KdfParams::interactive() { return {crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE}; }
KdfParams KdfParams::moderate() { return {crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE}; }
KdfParams KdfParams::testing() { return {crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN}; }

const char* statusMessage(StorageStatus s) {
    switch (s) {
        case StorageStatus::Ok: return "OK.";
        case StorageStatus::NotFound: return "Vault file not found.";
        case StorageStatus::AlreadyExists: return "A vault file already exists.";
        case StorageStatus::NotUnlocked: return "Vault is locked.";
        case StorageStatus::WrongPasswordOrCorrupt: return "Master password is incorrect, or the vault file has been modified.";
        case StorageStatus::Corrupt: return "Vault file is damaged or not a vault file.";
        case StorageStatus::UnsupportedVersion: return "Vault file was written by an unsupported version.";
        case StorageStatus::KdfFailed: return "Key derivation failed (not enough memory?).";
        case StorageStatus::IoError: return "Could not read or write the vault file.";
    }
    return "Unknown storage error.";
}

void VaultStorage::KeyDeleter::operator()(unsigned char* p) const { sodium_free(p); }  // sodium_free zeroes first

VaultStorage::VaultStorage(std::string path, KdfParams params) : path_(std::move(path)), params_(params) {
    initCrypto();
    std::memset(salt_, 0, sizeof salt_);
}

VaultStorage::~VaultStorage() { lock(); }

bool VaultStorage::exists() const {
    std::error_code ec;
    return fs::is_regular_file(path_, ec);
}

void VaultStorage::lock() { key_.reset(); }

StorageStatus VaultStorage::create(const std::string& pw, const std::string& plaintext) {
    if (exists()) return StorageStatus::AlreadyExists;   // never overwrite an existing vault
    std::error_code ec;
    fs::path parent = fs::path(path_).parent_path();
    if (!parent.empty()) fs::create_directories(parent, ec);

    randombytes_buf(salt_, sizeof salt_);
    KeyPtr key(static_cast<unsigned char*>(sodium_malloc(kKeyLen)));
    if (!key) return StorageStatus::KdfFailed;
    if (crypto_pwhash(key.get(), kKeyLen, pw.data(), pw.size(), salt_, params_.opslimit, params_.memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        return StorageStatus::KdfFailed;

    key_ = std::move(key);
    StorageStatus st = writeFile(plaintext);
    if (st != StorageStatus::Ok) key_.reset();
    return st;
}

StorageStatus VaultStorage::unlock(const std::string& pw, std::string& plaintextOut) {
    std::error_code ec;
    if (!fs::is_regular_file(path_, ec)) return StorageStatus::NotFound;
    std::uintmax_t size = fs::file_size(path_, ec);
    if (ec) return StorageStatus::IoError;
    if (size > kMaxFileSize || size < kHeaderLen + kTagLen) return StorageStatus::Corrupt;

    std::ifstream in(path_, std::ios::binary);
    if (!in) return StorageStatus::IoError;
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (buf.size() != size) return StorageStatus::IoError;

    if (std::memcmp(buf.data(), kMagic, 4) != 0) return StorageStatus::Corrupt;
    if (buf[4] != kVersion) return StorageStatus::UnsupportedVersion;
    std::uint64_t ops = getU64(&buf[5]), mem = getU64(&buf[13]);
    if (ops < 1 || ops > kMaxOps || mem < crypto_pwhash_MEMLIMIT_MIN || mem > kMaxMem) return StorageStatus::Corrupt;
    unsigned char salt[kSaltLen];
    std::memcpy(salt, &buf[21], kSaltLen);
    const unsigned char* nonce = &buf[kAdLen];
    const unsigned char* ct = &buf[kHeaderLen];
    const std::size_t ctLen = buf.size() - kHeaderLen;

    KeyPtr key(static_cast<unsigned char*>(sodium_malloc(kKeyLen)));
    if (!key) return StorageStatus::KdfFailed;
    if (crypto_pwhash(key.get(), kKeyLen, pw.data(), pw.size(), salt, ops, static_cast<std::size_t>(mem),
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        return StorageStatus::KdfFailed;

    std::vector<unsigned char> plain(ctLen - kTagLen);
    unsigned long long plainLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain.data(), &plainLen, nullptr, ct, ctLen, buf.data(), kAdLen,
                                                   nonce, key.get()) != 0)
        return StorageStatus::WrongPasswordOrCorrupt;   // file and current state stay untouched

    plaintextOut.assign(reinterpret_cast<const char*>(plain.data()), static_cast<std::size_t>(plainLen));
    if (!plain.empty()) sodium_memzero(plain.data(), plain.size());

    std::memcpy(salt_, salt, kSaltLen);
    params_ = {ops, static_cast<std::size_t>(mem)};
    key_ = std::move(key);
    return StorageStatus::Ok;
}

StorageStatus VaultStorage::save(const std::string& plaintext) {
    if (!key_) return StorageStatus::NotUnlocked;
    return writeFile(plaintext);
}

StorageStatus VaultStorage::writeFile(const std::string& plaintext) {
    std::vector<unsigned char> out(kHeaderLen + plaintext.size() + kTagLen);
    std::memcpy(out.data(), kMagic, 4);
    out[4] = kVersion;
    putU64(&out[5], params_.opslimit);
    putU64(&out[13], params_.memlimit);
    std::memcpy(&out[21], salt_, kSaltLen);
    randombytes_buf(&out[kAdLen], kNonceLen);            // fresh nonce for every write

    unsigned long long ctLen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(&out[kHeaderLen], &ctLen,
                                               reinterpret_cast<const unsigned char*>(plaintext.data()),
                                               plaintext.size(), out.data(), kAdLen, nullptr, &out[kAdLen],
                                               key_.get());
    out.resize(kHeaderLen + static_cast<std::size_t>(ctLen));

    const std::string tmp = path_ + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return StorageStatus::IoError;
        f.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
        f.flush();
        if (!f) { f.close(); std::error_code ec; fs::remove(tmp, ec); return StorageStatus::IoError; }
    }
    std::error_code ec;
    fs::rename(tmp, path_, ec);                           // atomic replace on POSIX; replaces on Windows too
    if (ec) {
        fs::remove(path_, ec);                            // fallback for platforms where rename won't overwrite
        std::error_code ec2;
        fs::rename(tmp, path_, ec2);
        if (ec2) return StorageStatus::IoError;
    }
    return StorageStatus::Ok;
}

}  // namespace ppm
