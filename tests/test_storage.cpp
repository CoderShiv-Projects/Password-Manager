#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

#include "crypto_util.h"
#include "storage.h"
#include "test_framework.h"

using namespace ppm;
namespace fs = std::filesystem;

namespace {
struct TempDir {
    fs::path path;
    TempDir() { path = fs::temp_directory_path() / ("ppm_test_" + randomHex(6)); fs::create_directories(path); }
    ~TempDir() { std::error_code ec; fs::remove_all(path, ec); }
    std::string file(const char* n = "vault.dat") const { return (path / n).string(); }
};
std::vector<char> slurp(const std::string& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
void spit(const std::string& p, const std::vector<char>& d) {
    std::ofstream o(p, std::ios::binary | std::ios::trunc);
    o.write(d.data(), static_cast<std::streamsize>(d.size()));
}
const char* kPw = "fake-master-password-123";
const char* kSecret = "{\"version\":1,\"entries\":[{\"password\":\"SUPER-SECRET-FAKE\"}]}";
}  // namespace

TEST(storage_create_unlock_round_trip_after_restart) {
    TempDir d;
    {
        VaultStorage s(d.file(), KdfParams::testing());
        CHECK(!s.exists());
        CHECK(s.create(kPw, kSecret) == StorageStatus::Ok);
        CHECK(s.isUnlocked());
    }
    VaultStorage again(d.file(), KdfParams::testing());   // simulates an application restart
    std::string out;
    CHECK(again.unlock(kPw, out) == StorageStatus::Ok);
    CHECK_EQ(out, std::string(kSecret));
}

TEST(storage_file_contains_no_plaintext) {
    TempDir d;
    VaultStorage s(d.file(), KdfParams::testing());
    s.create(kPw, kSecret);
    auto bytes = slurp(d.file());
    std::string blob(bytes.begin(), bytes.end());
    CHECK(blob.find("SUPER-SECRET-FAKE") == std::string::npos);
    CHECK(blob.find("password") == std::string::npos);
    CHECK(blob.compare(0, 4, "PPMV") == 0);
}

TEST(storage_save_uses_fresh_nonce_and_persists) {
    TempDir d;
    VaultStorage s(d.file(), KdfParams::testing());
    s.create(kPw, kSecret);
    auto first = slurp(d.file());
    CHECK(s.save(kSecret) == StorageStatus::Ok);          // identical plaintext...
    auto second = slurp(d.file());
    CHECK(first != second);                               // ...different bytes (new nonce)
    CHECK(s.save("{\"version\":1,\"entries\":[]}") == StorageStatus::Ok);
    VaultStorage r(d.file(), KdfParams::testing());
    std::string out;
    CHECK(r.unlock(kPw, out) == StorageStatus::Ok);
    CHECK_EQ(out, std::string("{\"version\":1,\"entries\":[]}"));
}

TEST(storage_wrong_master_password_fails_and_file_untouched) {
    TempDir d;
    { VaultStorage s(d.file(), KdfParams::testing()); s.create(kPw, kSecret); }
    auto before = slurp(d.file());
    VaultStorage s(d.file(), KdfParams::testing());
    std::string out;
    CHECK(s.unlock("wrong-password-xyz", out) == StorageStatus::WrongPasswordOrCorrupt);
    CHECK(!s.isUnlocked());
    CHECK(out.empty());
    CHECK(slurp(d.file()) == before);
}

TEST(storage_failed_unlock_keeps_existing_session) {
    TempDir d;
    VaultStorage s(d.file(), KdfParams::testing());
    s.create(kPw, kSecret);
    std::string out;
    CHECK(s.unlock("wrong-password-xyz", out) != StorageStatus::Ok);
    CHECK(s.isUnlocked());
    CHECK(s.save(kSecret) == StorageStatus::Ok);
}

TEST(storage_tampered_ciphertext_is_detected) {
    TempDir d;
    { VaultStorage s(d.file(), KdfParams::testing()); s.create(kPw, kSecret); }
    auto bytes = slurp(d.file());
    bytes[bytes.size() - 20] ^= 0x01;
    spit(d.file(), bytes);
    auto damaged = slurp(d.file());
    VaultStorage s(d.file(), KdfParams::testing());
    std::string out;
    CHECK(s.unlock(kPw, out) == StorageStatus::WrongPasswordOrCorrupt);
    CHECK(slurp(d.file()) == damaged);                    // never "repaired" or overwritten
}

TEST(storage_tampered_header_is_detected) {
    TempDir d;
    { VaultStorage s(d.file(), KdfParams::testing()); s.create(kPw, kSecret); }
    auto bytes = slurp(d.file());
    bytes[30] ^= 0x01;                                    // inside the salt
    spit(d.file(), bytes);
    VaultStorage s(d.file(), KdfParams::testing());
    std::string out;
    CHECK(s.unlock(kPw, out) == StorageStatus::WrongPasswordOrCorrupt);
}

TEST(storage_truncated_bad_magic_and_empty_files) {
    TempDir d;
    { VaultStorage s(d.file(), KdfParams::testing()); s.create(kPw, kSecret); }
    auto good = slurp(d.file());
    std::string out;

    spit(d.file(), std::vector<char>(good.begin(), good.begin() + 30));
    { VaultStorage s(d.file(), KdfParams::testing()); CHECK(s.unlock(kPw, out) == StorageStatus::Corrupt); }

    auto badMagic = good; badMagic[0] = 'X';
    spit(d.file(), badMagic);
    { VaultStorage s(d.file(), KdfParams::testing()); CHECK(s.unlock(kPw, out) == StorageStatus::Corrupt); }

    spit(d.file(), {});
    { VaultStorage s(d.file(), KdfParams::testing()); CHECK(s.unlock(kPw, out) == StorageStatus::Corrupt); }

    auto badVersion = good; badVersion[4] = 9;
    spit(d.file(), badVersion);
    { VaultStorage s(d.file(), KdfParams::testing()); CHECK(s.unlock(kPw, out) == StorageStatus::UnsupportedVersion); }
}

TEST(storage_refuses_to_overwrite_existing_vault) {
    TempDir d;
    VaultStorage a(d.file(), KdfParams::testing());
    a.create(kPw, kSecret);
    auto before = slurp(d.file());
    VaultStorage b(d.file(), KdfParams::testing());
    CHECK(b.create("another-fake-password", "{}") == StorageStatus::AlreadyExists);
    CHECK(slurp(d.file()) == before);
}

TEST(storage_missing_file_and_locked_save) {
    TempDir d;
    VaultStorage s(d.file("none.dat"), KdfParams::testing());
    std::string out;
    CHECK(s.unlock(kPw, out) == StorageStatus::NotFound);
    CHECK(s.save("{}") == StorageStatus::NotUnlocked);
    s.create(kPw, kSecret);
    s.lock();
    CHECK(!s.isUnlocked());
    CHECK(s.save("{}") == StorageStatus::NotUnlocked);
}
