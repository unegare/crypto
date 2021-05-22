#pragma once

#include <signal.h>

namespace sighandlers {
  extern bool flagToExit;

  bool setSigHandlers();

  void handler_ctrlc(int signum, siginfo_t* sinfo, void* ucontext);
}
