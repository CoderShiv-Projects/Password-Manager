#include "stack.h"

#include <utility>

namespace ppm {

UndoStack::UndoStack(std::size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {}

UndoStack::~UndoStack() { clear(); }

void UndoStack::push(DeletedRecord record) {
    top_ = new Node{std::move(record), top_};
    ++size_;
    if (size_ > capacity_) dropBottom();
}

bool UndoStack::pop(DeletedRecord& out) {
    if (!top_) return false;
    Node* n = top_;
    top_ = n->below;
    out = std::move(n->record);
    delete n;
    --size_;
    return true;
}

const DeletedRecord* UndoStack::peek() const { return top_ ? &top_->record : nullptr; }

void UndoStack::dropBottom() {
    if (!top_) return;
    if (!top_->below) {
        delete top_;
        top_ = nullptr;
    } else {
        Node* n = top_;
        while (n->below->below) n = n->below;
        delete n->below;
        n->below = nullptr;
    }
    --size_;
}

void UndoStack::clear() {
    while (top_) {
        Node* n = top_;
        top_ = n->below;
        delete n;
    }
    size_ = 0;
}

}  // namespace ppm
