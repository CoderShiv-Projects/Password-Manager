// stack.h - custom LIFO stack used to undo account deletions.
//
// Purpose: when an account is deleted, its entry (and the position it had in the
// list) is pushed here. "Undo" pops the newest record and re-inserts it, so the
// most recent deletion is always restored first (Last In, First Out).
//
//   top_ -> [record|below] -> [record|below] -> nullptr
//
// The stack is bounded (default 20 records) so decrypted passwords do not pile
// up in memory forever; when full, the OLDEST record at the bottom is dropped.
// It lives in memory only: after a restart or a vault lock it is empty.
#pragma once
#include <cstddef>

#include "password_entry.h"

namespace ppm {

struct DeletedRecord {
    PasswordEntry entry;
    std::size_t originalIndex = 0;   // position in the list when it was deleted
};

class UndoStack {
public:
    explicit UndoStack(std::size_t capacity = 20);
    ~UndoStack();
    UndoStack(const UndoStack&) = delete;
    UndoStack& operator=(const UndoStack&) = delete;

    void push(DeletedRecord record);
    bool pop(DeletedRecord& out);               // false when the stack is empty
    const DeletedRecord* peek() const;          // nullptr when empty
    bool empty() const { return size_ == 0; }
    std::size_t size() const { return size_; }
    std::size_t capacity() const { return capacity_; }
    void clear();

private:
    struct Node {
        DeletedRecord record;
        Node* below;
    };
    void dropBottom();

    Node* top_ = nullptr;
    std::size_t size_ = 0;
    std::size_t capacity_;
};

}  // namespace ppm
