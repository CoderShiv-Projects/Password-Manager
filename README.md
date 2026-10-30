# Personal Password Management and Account Credential Organization System

A college Computing Aptitude mini-project: a local password manager with a C++17 backend
(custom linked list + custom undo stack + encrypted vault file) and an HTML/CSS/vanilla-JS
interface served by the same C++ program.

> **College learning prototype.** It has **not** been professionally security audited.
> Use fake credentials only. Do not store real passwords in it.

## Features

Add / edit / delete accounts, delete confirmation and **Undo delete**, search by website or
username, category filter, password generator (length, lowercase, uppercase, numbers, symbols),
password reveal and copy, dashboard with statistics (weak and reused passwords flagged),
master-password vault with init / unlock / lock, auto-lock after 10 idle minutes, and
encrypted persistence between restarts.

## Technology stack

| Layer | Technology |
|---|---|
| Backend | C++17, [cpp-httplib](https://github.com/yhirose/cpp-httplib) 0.18.3 (vendored), [nlohmann/json](https://github.com/nlohmann/json) 3.11.3 (vendored) |
| Cryptography | libsodium: Argon2id key derivation + XChaCha20-Poly1305 authenticated encryption, CSPRNG |
| Build | CMake |
| Frontend | HTML5, CSS3, vanilla JavaScript, Fetch API |
| Data structures | Hand-written singly linked list and LIFO stack (no `std::vector`/`std::list` for the account collection) |

No Node.js, Python, database or frontend framework is used. (Node was only used once, outside
the project, to smoke-test the UI during development.)

## Project layout

```
PersonalPasswordManager/
├── backend/            C++ sources (one responsibility per module, see docs/FEATURE_MAP.md)
├── frontend/           index.html, css/style.css, js/app.js
├── tests/              dependency-free test harness + 53 tests
├── docs/               API.md, DATA_STRUCTURES.md, CPP_CONCEPTS.md, FEATURE_MAP.md, VIVA.md, PROJECT_REPORT.md
├── third_party/        httplib.h, nlohmann/json.hpp (vendored, pinned versions)
├── CMakeLists.txt
└── .gitignore          excludes build/, data/ (vault files), *.dat, keys
```

## Windows setup (MSYS2 + GCC + CMake)

1. Install MSYS2 from <https://www.msys2.org> (default folder `C:\msys64`).
2. Open the **MSYS2 MINGW64** shell (not the plain "MSYS" shell) and update:
   ```bash
   pacman -Syu          # the window may close; reopen MSYS2 MINGW64 and run it once more
   ```
3. Install the toolchain and libsodium:
   ```bash
   pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
                      mingw-w64-x86_64-libsodium mingw-w64-x86_64-pkgconf
   ```
4. **Verify** the dependencies (each command must print a version, otherwise stop and fix it):
   ```bash
   g++ --version
   cmake --version
   pkg-config --modversion libsodium
   ```
5. Build (adjust the path to where you unpacked the project):
   ```bash
   cd /c/Users/YOU/PersonalPasswordManager
   cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
   cmake --build build
   ```
   (Without Ninja use `-G "MinGW Makefiles"`.) CMake stops with a clear message if libsodium is missing.
6. Run the tests, then start the server:
   ```bash
   cd build && ctest --output-on-failure && cd ..
   ./build/password_manager.exe
   ```
7. Open <http://127.0.0.1:8080> in a browser. On first start you create the master password
   (at least 12 characters). **There is no recovery if you forget it.**

Stop the server with `Ctrl+C`. The vault is stored in `data/vault.dat` inside the project folder.

### Linux / macOS

```bash
sudo apt install build-essential cmake pkg-config libsodium-dev   # Ubuntu / Debian
cmake -S . -B build && cmake --build build
cd build && ctest --output-on-failure && cd ..
./build/password_manager
```

### Command-line options

```
--port N          listen port (default 8080)
--vault PATH      vault file (default <project>/data/vault.dat)
--frontend DIR    folder holding index.html, css/, js/
--kdf MODE        moderate (default, 256 MiB, about 1 s) | interactive (64 MiB); applies when a vault is created
--idle-minutes N  auto-lock delay (default 10)
--host ADDR       must be 127.0.0.1 / localhost / ::1; other addresses are refused
```

## Running the tests

```bash
cd build
ctest --output-on-failure          # or run ./tests/ppm_tests directly
./tests/ppm_tests storage          # run only tests whose name contains "storage"
```

The suite covers: linked list (empty list, head/tail/middle deletion, insert positions, ownership
transfer), stack (empty, LIFO, bounded capacity), account add/search/edit/delete/undo, duplicate
websites and usernames, generator configurations, encrypted storage (round trip after
"restart", wrong master password, bit-flipped ciphertext, tampered header, truncated / empty /
wrong-magic files, no overwrite of damaged vaults), and the HTTP API (auth, CSRF/Host checks,
malformed JSON, missing fields, wrong content type, oversized body, error codes, static-file
traversal, idle auto-lock, persistence across server restarts). Tests use only fake data and a
low-cost KDF setting so they run quickly.

### What was actually verified

| Check | Result |
|---|---|
| Build on Ubuntu 24.04, GCC 13.3, CMake 3.28, libsodium 1.0.18 | built without warnings (`-Wall -Wextra`) |
| `ppm_tests` | **53 / 53 passed** |
| Same tests under AddressSanitizer + UBSan + LeakSanitizer | 53 / 53 passed, no reports |
| Scripted UI walk-through (jsdom) against the running C++ server: create vault, add, edit, search, filter, reveal, copy, delete, undo, generator, lock, wrong password, unlock | 35 / 35 checks passed |
| Vault file inspected after use | starts with `PPMV`, contains no plaintext |

**Not verified:** the Windows / MSYS2 build itself (I could only build on Linux), and the visual
appearance in a real browser (jsdom does not render CSS). The Windows instructions follow
the standard MSYS2 package names, but if a step fails on your machine, see Troubleshooting.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `libsodium was not found` from CMake | Run step 3 in the **MINGW64** shell; check `pkg-config --modversion libsodium` prints a version. |
| `pkg-config: command not found` | `pacman -S mingw-w64-x86_64-pkgconf` |
| `cmake: command not found` / wrong compiler picked | You are in the wrong MSYS2 shell. Use "MSYS2 MINGW64". Delete `build/` and configure again. |
| `The C++ compiler is not able to compile a simple test program` | Delete `build/`; make sure `g++ --version` works in the same shell. |
| `libsodium-26.dll was not found` when double-clicking the .exe | Run from the MINGW64 shell, add `C:\msys64\mingw64\bin` to PATH, or rebuild with `-DPPM_STATIC_LINK=ON`. |
| `Error: could not listen on 127.0.0.1:8080` | Port in use. Start with `--port 8081`. |
| Browser shows "This site can't be reached" | Server not running, or wrong port. Use exactly the URL printed at start-up. |
| Page loads but says "Cannot reach the local server" | The server was stopped. Restart it. |
| `Error: could not find frontend/index.html` | Start the program from the project folder, or pass `--frontend <path>`. |
| Out-of-memory / "Key derivation failed" | Start with `--kdf interactive` when creating the vault (64 MiB instead of 256 MiB). |
| "Too many failed attempts" | Five wrong master passwords trigger a 30-second lock-out. Wait and retry. |
| "Vault file is damaged" | The program never overwrites a damaged vault. Restore a backup copy of `data/vault.dat`, or move the file away to start a new vault (old data is then unreadable). |
| Forgot the master password | Not recoverable by design. |

## Security design (summary)

* Key derivation: Argon2id (`crypto_pwhash`), random 16-byte salt, parameters stored in the file header.
* Encryption: XChaCha20-Poly1305 (`crypto_aead_xchacha20poly1305_ietf`), fresh 24-byte random nonce on every save; the header is authenticated as additional data.
* The master password and plaintext vault are never written to disk; the derived key lives in libsodium guarded memory and is wiped on lock.
* A wrong password or damaged file never modifies the vault file; `init` refuses to overwrite an existing vault. Saves go to a temp file, then replace the vault.
* List responses never contain passwords. Only `GET /api/accounts/:id` returns one, and only for an unlocked session.
* The server binds to `127.0.0.1`, checks the `Host` header (anti DNS-rebinding), requires a custom header plus same-origin `Origin` on every state-changing request (CSRF), uses an `HttpOnly; SameSite=Strict` session cookie, caps request bodies at 64 KiB, serves only four whitelisted static files, and sends CSP and other security headers.
* Failed unlocks: 5 in a row trigger a 30-second lock-out; the vault auto-locks after 10 idle minutes.
* Passwords are generated with libsodium's CSPRNG (`randombytes_uniform`), never `rand()`.

### Known limitations (honest list)

* Decrypted passwords exist in process memory while unlocked. Copies made by the C++ runtime, JSON library and the browser cannot all be wiped. No protection against malware on the same PC.
* Undo history is memory-only: after a restart or lock, deleted accounts cannot be restored. Undo stack holds at most 20 deletions.
* No master-password change, no export/import, no multi-user support, no HTTPS (traffic stays on the loopback interface).
* The idle auto-lock is enforced on the next request or status poll (the browser polls every 15 s), not by a background thread.
* The clipboard is not cleared automatically after copying.
* `fsync` is not called before the atomic rename, so a power cut during a save could still lose the latest change on some systems.

## Documentation

* [docs/API.md](docs/API.md) - endpoints, request/response examples, status codes
* [docs/DATA_STRUCTURES.md](docs/DATA_STRUCTURES.md) - linked list and stack explained
* [docs/CPP_CONCEPTS.md](docs/CPP_CONCEPTS.md) - classes, strings, pointers, linked list, stack
* [docs/FEATURE_MAP.md](docs/FEATURE_MAP.md) - feature to source-file mapping
* [docs/VIVA.md](docs/VIVA.md) - viva questions and answers
* [docs/PROJECT_REPORT.md](docs/PROJECT_REPORT.md) - architecture, design decisions, results
