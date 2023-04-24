#pragma once

#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>

template <class T>
class ThreadSafeQueue {
public:
  ThreadSafeQueue() :
  q(),
  m(),
  c(),
  e(),
  canceled(false)
{

}

~ThreadSafeQueue() {
  e.notify_all();
}

void enqueue(std::shared_ptr<T> t) {
  std::lock_guard<std::mutex> lock(m);
  q.push(std::move(t));
  c.notify_one();
}

// Waits until an element is available;
// only returns nullptr if queue is canceled
std::shared_ptr<T> dequeue() {
  std::unique_lock<std::mutex> lock(m);
  while(q.empty() && !canceled) {
    // release lock as long as waiting; reaquire lock afterwards.
    c.wait(lock);
  }

  std::shared_ptr<T> result = nullptr;
  if(!canceled) {
      result = std::move(q.front());
      q.pop();
      e.notify_all(); //notify if anyone waits for empty queue
  }
  return result;
}

// Immediately returns an element or nullptr if empty/canceled
std::shared_ptr<T> dequeueImmediate() {
  std::unique_lock<std::mutex> lock(m);
  std::shared_ptr<T> result = nullptr;
  if(!q.empty()) {
      result = std::move(q.front());
      q.pop();
      e.notify_all(); //notify if anyone waits for empty queue
  }
  return result;
}

void cancel() {
  std::lock_guard<std::mutex> lock(m);
  canceled = true;
  c.notify_all();   //wake all waiting consumers
}

bool waitEmpty() {
  std::unique_lock<std::mutex> lock(m);
  while(!q.empty() && !canceled) {
    e.wait(lock);
  }
  return q.empty();
}

bool isEmpty() {return q.empty();}

private:
  std::queue<std::shared_ptr<T>> q;
  mutable std::mutex m;
  std::condition_variable c;
  std::condition_variable e;
  bool canceled;
};

