#include "linked_list.h"

#include <utility>

namespace ppm {

LinkedList::~LinkedList() { clear(); }

LinkedList::LinkedList(LinkedList&& o) noexcept : head_(o.head_), tail_(o.tail_), size_(o.size_) {
    o.head_ = o.tail_ = nullptr;
    o.size_ = 0;
}

LinkedList& LinkedList::operator=(LinkedList&& o) noexcept {
    if (this != &o) {
        clear();
        head_ = o.head_;
        tail_ = o.tail_;
        size_ = o.size_;
        o.head_ = o.tail_ = nullptr;
        o.size_ = 0;
    }
    return *this;
}

void LinkedList::pushBack(PasswordEntry entry) {
    Node* n = new Node(std::move(entry));
    if (tail_) tail_->next = n; else head_ = n;
    tail_ = n;
    ++size_;
}

void LinkedList::pushFront(PasswordEntry entry) {
    Node* n = new Node(std::move(entry));
    n->next = head_;
    head_ = n;
    if (!tail_) tail_ = n;
    ++size_;
}

bool LinkedList::insertAt(std::size_t index, PasswordEntry entry) {
    if (index > size_) return false;
    if (index == 0) { pushFront(std::move(entry)); return true; }
    if (index == size_) { pushBack(std::move(entry)); return true; }
    Node* prev = head_;
    for (std::size_t i = 1; i < index; ++i) prev = prev->next;  // stop at node index-1
    Node* n = new Node(std::move(entry));
    n->next = prev->next;
    prev->next = n;
    ++size_;
    return true;
}

PasswordEntry* LinkedList::findById(const std::string& id) {
    for (Node* cur = head_; cur; cur = cur->next)
        if (cur->data.id() == id) return &cur->data;
    return nullptr;
}

const PasswordEntry* LinkedList::findById(const std::string& id) const {
    for (const Node* cur = head_; cur; cur = cur->next)
        if (cur->data.id() == id) return &cur->data;
    return nullptr;
}

bool LinkedList::removeById(const std::string& id, PasswordEntry* removedOut, std::size_t* indexOut) {
    Node* prev = nullptr;
    Node* cur = head_;
    std::size_t idx = 0;
    while (cur && cur->data.id() != id) {
        prev = cur;
        cur = cur->next;
        ++idx;
    }
    if (!cur) return false;                 // not found (also covers the empty list)

    if (prev) prev->next = cur->next;       // middle or last node
    else head_ = cur->next;                 // removing the head
    if (cur == tail_) tail_ = prev;         // removing the last node (prev may be nullptr)

    if (removedOut) *removedOut = std::move(cur->data);
    if (indexOut) *indexOut = idx;
    delete cur;
    --size_;
    return true;
}

void LinkedList::forEach(const std::function<void(const PasswordEntry&)>& fn) const {
    for (const Node* cur = head_; cur; cur = cur->next) fn(cur->data);
}

void LinkedList::clear() {
    Node* cur = head_;
    while (cur) {               // iterative: a recursive delete could overflow the stack
        Node* next = cur->next;
        delete cur;
        cur = next;
    }
    head_ = tail_ = nullptr;
    size_ = 0;
}

}  // namespace ppm
