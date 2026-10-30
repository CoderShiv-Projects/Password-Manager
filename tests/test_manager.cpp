#include "password_manager.h"
#include "test_framework.h"

using namespace ppm;

static AccountInput input(const char* w, const char* u, const char* p, const char* c) {
    AccountInput in; in.website = w; in.username = u; in.password = p; in.category = c; return in;
}

TEST(manager_add_account_and_unique_ids) {
    PasswordManager m; AccountMeta a, b;
    CHECK(m.addAccount(input("example.test", "alice@example.test", "Fake-Pass-1!", "Social"), a).ok());
    CHECK(m.addAccount(input("example.test", "alice@example.test", "Fake-Pass-2!", "Social"), b).ok());
    CHECK_EQ(m.size(), std::size_t(2));
    CHECK(a.id != b.id);
    CHECK_EQ(a.id.size(), std::size_t(32));
}

TEST(manager_validation_rejects_bad_input) {
    PasswordManager m; AccountMeta x;
    CHECK(m.addAccount(input("", "u", "p", "Work"), x).code == ErrorCode::Validation);
    CHECK(m.addAccount(input("   ", "u", "p", "Work"), x).code == ErrorCode::Validation);
    CHECK(m.addAccount(input("s", "", "p", "Work"), x).code == ErrorCode::Validation);
    CHECK(m.addAccount(input("s", "u", "", "Work"), x).code == ErrorCode::Validation);
    CHECK(m.addAccount(input("s", "u", "p", "NotACategory"), x).code == ErrorCode::Validation);
    CHECK(m.addAccount(input("s", "u", "p\nq", "Work"), x).code == ErrorCode::Validation);
    CHECK(m.addAccount(input(std::string(101, 'a').c_str(), "u", "p", "Work"), x).code == ErrorCode::Validation);
    AccountInput missing; missing.website = "only-site";
    OpResult r = m.addAccount(missing, x);
    CHECK(r.code == ErrorCode::Validation); CHECK_EQ(r.field, std::string("username"));
    CHECK_EQ(m.size(), std::size_t(0));
}

TEST(manager_trims_website_and_username) {
    PasswordManager m; AccountMeta a;
    CHECK(m.addAccount(input("  example.test  ", "  bob  ", "Fake-Pass-1!", "Work"), a).ok());
    CHECK_EQ(a.website, std::string("example.test"));
    CHECK_EQ(a.username, std::string("bob"));
}

TEST(manager_search_and_category_filter) {
    PasswordManager m; AccountMeta x;
    m.addAccount(input("GitHub", "dev@example.test", "Fake-Pass-1!", "Development"), x);
    m.addAccount(input("GitLab", "team@example.test", "Fake-Pass-2!", "Work"), x);
    m.addAccount(input("Bank", "dev@example.test", "Fake-Pass-3!", "Finance"), x);
    CHECK_EQ(m.search("", "").size(), std::size_t(3));
    CHECK_EQ(m.search("git", "").size(), std::size_t(2));          // case-insensitive website
    CHECK_EQ(m.search("DEV@", "").size(), std::size_t(2));         // username match
    CHECK_EQ(m.search("git", "Work").size(), std::size_t(1));
    CHECK_EQ(m.search("", "Finance").size(), std::size_t(1));
    CHECK_EQ(m.search("zzz", "").size(), std::size_t(0));
}

TEST(manager_edit_account_partial_and_invalid) {
    PasswordManager m; AccountMeta a, u;
    m.addAccount(input("old.test", "u", "Fake-Pass-1!", "Other"), a);
    AccountInput e; e.website = "new.test"; e.category = "Shopping";
    CHECK(m.updateAccount(a.id, e, u).ok());
    CHECK_EQ(u.website, std::string("new.test"));
    CHECK_EQ(m.find(a.id)->password(), std::string("Fake-Pass-1!"));   // untouched
    AccountInput p; p.password = "Fake-Pass-9!";
    CHECK(m.updateAccount(a.id, p, u).ok());
    CHECK_EQ(m.find(a.id)->password(), std::string("Fake-Pass-9!"));

    AccountInput bad; bad.website = "ok.test"; bad.category = "Nope";
    CHECK(m.updateAccount(a.id, bad, u).code == ErrorCode::Validation);
    CHECK_EQ(m.find(a.id)->website(), std::string("new.test"));        // no half-applied edit
    CHECK(m.updateAccount(a.id, AccountInput{}, u).code == ErrorCode::Validation);
    CHECK(m.updateAccount("missing", e, u).code == ErrorCode::NotFound);
}

TEST(manager_delete_and_undo_restores_position) {
    PasswordManager m; AccountMeta a, b, c, out;
    m.addAccount(input("a.test", "u", "Fake-Pass-1!", "Other"), a);
    m.addAccount(input("b.test", "u", "Fake-Pass-2!", "Other"), b);
    m.addAccount(input("c.test", "u", "Fake-Pass-3!", "Other"), c);
    CHECK(m.deleteAccount(b.id, out).ok());
    CHECK_EQ(m.size(), std::size_t(2));
    CHECK_EQ(m.undoDepth(), std::size_t(1));
    CHECK(m.find(b.id) == nullptr);
    CHECK(m.undoDelete(out).ok());
    CHECK_EQ(out.id, b.id);
    CHECK_EQ(m.find(b.id)->password(), std::string("Fake-Pass-2!"));
    auto all = m.search("", "");
    CHECK_EQ(all[1].id, b.id);                       // back in the middle
}

TEST(manager_undo_is_lifo_and_empty_is_graceful) {
    PasswordManager m; AccountMeta a, b, out;
    CHECK(m.undoDelete(out).code == ErrorCode::NothingToUndo);
    m.addAccount(input("a.test", "u", "Fake-Pass-1!", "Other"), a);
    m.addAccount(input("b.test", "u", "Fake-Pass-2!", "Other"), b);
    m.deleteAccount(a.id, out);
    m.deleteAccount(b.id, out);
    CHECK(m.undoDelete(out).ok()); CHECK_EQ(out.id, b.id);
    CHECK(m.undoDelete(out).ok()); CHECK_EQ(out.id, a.id);
    CHECK(m.undoDelete(out).code == ErrorCode::NothingToUndo);
    CHECK(m.deleteAccount("missing", out).code == ErrorCode::NotFound);
}

TEST(manager_delete_head_and_last_nodes) {
    PasswordManager m; AccountMeta a, b, c, out;
    m.addAccount(input("a.test", "u", "Fake-Pass-1!", "Other"), a);
    m.addAccount(input("b.test", "u", "Fake-Pass-2!", "Other"), b);
    m.addAccount(input("c.test", "u", "Fake-Pass-3!", "Other"), c);
    CHECK(m.deleteAccount(a.id, out).ok());          // head
    CHECK(m.deleteAccount(c.id, out).ok());          // last
    CHECK_EQ(m.size(), std::size_t(1));
    AccountMeta d;
    CHECK(m.addAccount(input("d.test", "u", "Fake-Pass-4!", "Other"), d).ok());
    CHECK_EQ(m.search("", "").size(), std::size_t(2));
}

TEST(manager_weak_and_reused_flags) {
    PasswordManager m; AccountMeta a, b, c;
    m.addAccount(input("a.test", "u", "short", "Other"), a);
    m.addAccount(input("b.test", "u", "Str0ng-Fake-Pass!", "Other"), b);
    m.addAccount(input("c.test", "u", "Str0ng-Fake-Pass!", "Other"), c);
    auto all = m.search("", "");
    CHECK(all[0].weak); CHECK(!all[1].weak);
    CHECK(!all[0].reused); CHECK(all[1].reused); CHECK(all[2].reused);
    VaultStats s = m.stats();
    CHECK_EQ(s.total, std::size_t(3)); CHECK_EQ(s.weak, std::size_t(1)); CHECK_EQ(s.reused, std::size_t(2));
}

TEST(manager_json_round_trip_and_rejects_garbage) {
    PasswordManager m; AccountMeta a;
    m.addAccount(input("a.test", "u1", "Fake-Pass-1!", "Work"), a);
    m.addAccount(input("b.test", "u2", "Fake-Pass-2!", "Social"), a);
    std::string json = m.toJson();
    PasswordManager n;
    CHECK(n.loadJson(json).ok());
    CHECK_EQ(n.size(), std::size_t(2));
    CHECK_EQ(n.search("b.test", "")[0].username, std::string("u2"));
    CHECK(!n.loadJson("not json").ok());
    CHECK(!n.loadJson("{\"version\":2,\"entries\":[]}").ok());
    CHECK(!n.loadJson("{\"version\":1,\"entries\":[{\"id\":\"x\"}]}").ok());
    CHECK_EQ(n.size(), std::size_t(2));              // failed load keeps previous data
}

TEST(manager_rejects_duplicate_ids_on_load) {
    const char* doc = "{\"version\":1,\"entries\":["
        "{\"id\":\"1\",\"website\":\"a\",\"username\":\"u\",\"password\":\"p\",\"category\":\"Work\"},"
        "{\"id\":\"1\",\"website\":\"b\",\"username\":\"u\",\"password\":\"p\",\"category\":\"Work\"}]}";
    PasswordManager m;
    CHECK(!m.loadJson(doc).ok());
}
