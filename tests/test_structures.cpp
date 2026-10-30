#include "linked_list.h"
#include "stack.h"
#include "test_framework.h"

using namespace ppm;

static PasswordEntry make(const std::string& id, const std::string& site = "site.test") {
    return PasswordEntry(id, site, "user@example.test", "Fake-Pass-1!", "Other", 1, 1);
}

TEST(list_empty_list_is_safe) {
    LinkedList l;
    CHECK(l.empty());
    CHECK_EQ(l.size(), std::size_t(0));
    CHECK(l.findById("x") == nullptr);
    CHECK(!l.removeById("x"));
    CHECK(l.head() == nullptr);
    l.clear();
    CHECK(l.empty());
}

TEST(list_push_find_traverse) {
    LinkedList l;
    l.pushBack(make("a"));
    l.pushBack(make("b"));
    l.pushFront(make("z"));
    CHECK_EQ(l.size(), std::size_t(3));
    std::string order;
    l.forEach([&](const PasswordEntry& e) { order += e.id(); });
    CHECK_EQ(order, std::string("zab"));
    CHECK(l.findById("b") != nullptr);
    CHECK(l.findById("nope") == nullptr);
}

TEST(list_edit_through_pointer) {
    LinkedList l;
    l.pushBack(make("a"));
    l.findById("a")->setWebsite("changed.test");
    CHECK_EQ(l.findById("a")->website(), std::string("changed.test"));
}

TEST(list_insert_at_positions) {
    LinkedList l;
    l.pushBack(make("a")); l.pushBack(make("c"));
    CHECK(l.insertAt(1, make("b")));
    CHECK(l.insertAt(0, make("0")));
    CHECK(l.insertAt(4, make("d")));
    CHECK(!l.insertAt(99, make("bad")));
    std::string order;
    l.forEach([&](const PasswordEntry& e) { order += e.id(); });
    CHECK_EQ(order, std::string("0abcd"));
}

TEST(list_delete_head_middle_and_tail) {
    LinkedList l;
    for (const char* id : {"a", "b", "c", "d"}) l.pushBack(make(id));
    PasswordEntry out; std::size_t idx = 99;
    CHECK(l.removeById("a", &out, &idx));          // head
    CHECK_EQ(out.id(), std::string("a")); CHECK_EQ(idx, std::size_t(0));
    CHECK(l.removeById("d", &out, &idx));          // tail
    CHECK_EQ(idx, std::size_t(2));
    CHECK(l.removeById("b"));                      // middle
    CHECK_EQ(l.size(), std::size_t(1));
    l.pushBack(make("e"));                         // tail pointer must still be valid
    std::string order;
    l.forEach([&](const PasswordEntry& e) { order += e.id(); });
    CHECK_EQ(order, std::string("ce"));
    CHECK(l.removeById("c")); CHECK(l.removeById("e"));
    CHECK(l.empty());
    l.pushBack(make("again"));                     // reuse after becoming empty
    CHECK_EQ(l.size(), std::size_t(1));
}

TEST(list_move_transfers_ownership) {
    LinkedList a;
    a.pushBack(make("a"));
    LinkedList b(std::move(a));
    CHECK(a.empty());
    CHECK_EQ(b.size(), std::size_t(1));
    LinkedList c;
    c = std::move(b);
    CHECK(b.empty());
    CHECK(c.findById("a") != nullptr);
}

TEST(list_duplicate_websites_and_usernames_get_separate_nodes) {
    LinkedList l;
    l.pushBack(make("1", "same.test"));
    l.pushBack(make("2", "same.test"));
    CHECK_EQ(l.size(), std::size_t(2));
    CHECK(l.removeById("1"));
    CHECK(l.findById("2") != nullptr);
}

TEST(stack_empty_behaviour) {
    UndoStack s;
    DeletedRecord r;
    CHECK(s.empty());
    CHECK(!s.pop(r));
    CHECK(s.peek() == nullptr);
    CHECK_EQ(s.size(), std::size_t(0));
}

TEST(stack_is_last_in_first_out) {
    UndoStack s;
    for (const char* id : {"a", "b", "c"}) s.push({make(id), 0});
    CHECK_EQ(s.peek()->entry.id(), std::string("c"));
    DeletedRecord r;
    CHECK(s.pop(r)); CHECK_EQ(r.entry.id(), std::string("c"));
    CHECK(s.pop(r)); CHECK_EQ(r.entry.id(), std::string("b"));
    CHECK(s.pop(r)); CHECK_EQ(r.entry.id(), std::string("a"));
    CHECK(!s.pop(r));
}

TEST(stack_drops_oldest_when_full) {
    UndoStack s(2);
    for (const char* id : {"a", "b", "c"}) s.push({make(id), 0});
    CHECK_EQ(s.size(), std::size_t(2));
    DeletedRecord r;
    CHECK(s.pop(r)); CHECK_EQ(r.entry.id(), std::string("c"));
    CHECK(s.pop(r)); CHECK_EQ(r.entry.id(), std::string("b"));
    CHECK(!s.pop(r));
    UndoStack one(1);
    one.push({make("x"), 0}); one.push({make("y"), 0});
    CHECK_EQ(one.size(), std::size_t(1));
    CHECK_EQ(one.peek()->entry.id(), std::string("y"));
}

TEST(stack_clear_empties) {
    UndoStack s;
    s.push({make("a"), 0}); s.push({make("b"), 1});
    s.clear();
    CHECK(s.empty());
}
