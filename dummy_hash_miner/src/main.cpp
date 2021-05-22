#include <iostream>
#include <sstream>
#include <fstream>
#include <thread>
#include <string_view>
#include <ranges>
#include <boost/format.hpp>

#include <miner.h>
#include <sighandlers.h>
#include <log.h>

int main(int argc, char *argv[]) {

  logging::init();
  boost::log::add_common_attributes();

  if (!sighandlers::setSigHandlers()) {
    BOOST_LOG_TRIVIAL(error) << "setSigHandlers failed";
    return 0;
  }

  if (argc > 2) {
    BOOST_LOG_TRIVIAL(error) << "{\n\t\"message\": \"ERROR: too many arguments. It can receive just one argumet. It must be a file name to store founded solutions.\"\n}";
  }

  std::unique_lock<std::mutex> lk(miner::m_recieved);
  std::list<std::thread> ths;
  for (size_t i = 0; i < std::thread::hardware_concurrency(); i++)
    ths.emplace_back([](){miner::Task task; task();});

  std::size_t solutions_already_processed = 0;
  std::size_t messages_already_processed = 0;

  while(!sighandlers::flagToExit) {
    miner::cv.wait(lk, []{return miner::ready || sighandlers::flagToExit;});
    if (miner::ready) {
      for (const auto& it : miner::messages | std::ranges::views::drop(messages_already_processed)) {
        switch(it->getType()) {
          case Message::MessageType::randomInitValueSet: {
            BOOST_LOG_TRIVIAL(trace) << it->toJSON();
            break;
          }
          default: BOOST_LOG_TRIVIAL(info) << it->toJSON();
        }
        messages_already_processed++;
      }
      miner::ready = false;
    }
  }

  BOOST_LOG_TRIVIAL(info) << "{\n\t\"message\": \"exit...\"\n}";

  if (argc >= 2) {
    std::ofstream file(argv[1]);
    if (file.is_open()) {
      auto filt = [](const std::unique_ptr<Message> &m) -> bool {return m->getType() == Message::MessageType::newSolution;};
      file<< "[";
      for (const auto& it : miner::messages | std::ranges::views::filter(filt) | std::ranges::views::take(1)) {
        file << '\n' << it->toJSON();
      }
      for (const auto& it : miner::messages | std::ranges::views::filter(filt) | std::ranges::views::drop(1)) {
        file << ",\n" << it->toJSON();
      }
      file << "\n]";
      file.close();
    } else {
      BOOST_LOG_TRIVIAL(error) << boost::format("{\n\t\"message\": \"ERROR: cannot open the '%s' file.\"}") % argv[1];
    }
  } else {
    BOOST_LOG_TRIVIAL(info) << R"({"message": "argc < 2 ???"})";
  }

  for (auto& el : ths) el.join();
//  for (const auto& el : miner::messages) delete el;
  miner::messages.clear();
  return 0;
}
