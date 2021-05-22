#include <signal.h>

#include <sighandlers.h>

namespace sighandlers {
  struct sigaction sgact;

  bool flagToExit = false;

bool setSigHandlers() {
  sigemptyset(&sgact.sa_mask);
  sgact.sa_handler = nullptr;
  sgact.sa_sigaction = handler_ctrlc;
  sgact.sa_flags = SA_SIGINFO;
  if (sigaction(SIGINT, &sgact, nullptr)) {
    return false;
  }
  return true;
}

void handler_ctrlc(int signum, siginfo_t* sinfo, void* ucontext) {
  flagToExit = true;
}

}
