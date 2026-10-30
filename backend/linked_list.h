// linked_list.h - hand-written singly linked list that owns every PasswordEntry.
//
//   head_ -> [entry|next] -> [entry|next] -> [entry|next] -> nullptr
//                                                ^
//                                              tail_
//
// Ownership rule: the list owns every Node it allocated with `new` and frees
// each one with `delete` (in removeById, clear and the destructor).
#pragma once
#include <cstddef>
#include <functional>
#include <string>

#include "password_entry.h"

namespace ppm {

class LinkedList {
public:
    struct Node {
        PasswordEntry data;
        Node* next;
        explicit Node(PasswordEntry e) : data(std::move(e)), next(nullptr) {}
    };

    LinkedList() = default;
    ~LinkedList();
    LinkedList(const LinkedList&) = delete;             // one owner per node chain
    LinkedList& operator=(const LinkedList&) = delete;
    LinkedList(LinkedList&& other) noexcept;
    LinkedList& operator=(LinkedList&& other) noexcept;

    // Insertion
    void pushBack(PasswordEntry entry);                  // O(1) thanks to tail_
    void pushFront(PasswordEntry entry);                 // O(1)
    bool insertAt(std::size_t index, PasswordEntry entry);  // false if index > size()

    // Search / edit (edit = modify through the returned pointer)
    PasswordEntry* findById(const std::string& id);
    const PasswordEntry* findById(const std::string& id) const;

    // Deletion: unlinks the node, optionally moves its entry out, frees the node.
    bool removeById(const std::string& id, PasswordEntry* removedOut = nullptr,
                    std::size_t* indexOut = nullptr);

    // Traversal
    void forEach(const std::function<void(const PasswordEntry&)>& fn) const;
    const Node* head() const { return head_; }

    std::size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }
    void clear();

private:
    Node* head_ = nullptr;
    Node* tail_ = nullptr;
    std::size_t size_ = 0;
};

}  // namespace ppm
