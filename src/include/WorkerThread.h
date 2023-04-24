#pragma once

#include "SubframeWorker.h"
#include "ThreadSafeQueue.h"
#include <future>

#include "srsran/common/threads.h"

//#define MAX_WORKER_BUFFER 30

class SubframeWorkerThread : public srsran::thread {
public:
    SubframeWorkerThread(ThreadSafeQueue<SubframeWorker>& avail,
                         ThreadSafeQueue<SubframeWorker>& pending);
    virtual ~SubframeWorkerThread();
    void cancel();
    void wait_thread_finish();
protected:
  virtual void run_thread() override;
private:
  const std::string threadname = "workerthread";
  ThreadSafeQueue<SubframeWorker>& avail;
  ThreadSafeQueue<SubframeWorker>& pending;
  volatile bool canceled;
  volatile bool joined;
};

class SnifferThread {
public:
    SnifferThread(ThreadSafeQueue<SubframeWorker>& avail,
                  ThreadSafeQueue<SubframeWorker>& pending,
                  std::future<void>              & thread_return);
    virtual ~SnifferThread();
    void    cancel();
    void    wait_thread_finish();
    void    execute_worker();
    void    run_thread();
private:
  const std::string threadname = "workerthread";
  ThreadSafeQueue<SubframeWorker>& avail;
  ThreadSafeQueue<SubframeWorker>& pending;
  std::future<void>                thread_return;
  volatile bool canceled;
  volatile bool joined;
};