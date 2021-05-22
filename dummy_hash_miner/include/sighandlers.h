#pragma once

#include <signal.h>

#include <atomic>

namespace sighandlers {
  extern std::atomic_bool flagToExit;

  bool setSigHandlers();

  void handler_ctrlc(int signum, siginfo_t* sinfo, void* ucontext);
}
