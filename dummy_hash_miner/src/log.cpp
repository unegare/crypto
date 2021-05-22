#include <boost/date_time/posix_time/posix_time.hpp>

#include <log.h>

namespace logging {

void init() {
  namespace bl = boost::log;

  boost::log::register_simple_formatter_factory<boost::log::trivial::severity_level, char>("Severity");

  bl::add_file_log(
    bl::keywords::file_name = "log_%N.log",
    bl::keywords::auto_flush = true,
    bl::keywords::rotation_size = 1000,
    bl::keywords::time_based_rotation = bl::sinks::file::rotation_at_time_interval(boost::posix_time::seconds(10)),
    bl::keywords::format = "[%TimeStamp%]: <%Severity%>: %Message%",

    bl::keywords::target = "logs",
    bl::keywords::max_size = 1000,
    bl::keywords::max_files = 2
  );
  bl::add_console_log(std::clog, bl::keywords::format = "[%TimeStamp%]: <%Severity%>: %Message%");

//  using sink_t = bl::sinks::synchronous_sink<bl::sinks::text_ostream_backend>;
//
//  boost::shared_ptr<bl::core> core = bl::core::get();
//
//  boost::shared_ptr<sinks::text_ostream_backend> backend = boost::make_shared<bl::sinks::text_ostream_backend>();
//
//  
//
//  boost::shared_ptr<sink_t> sink(new sink_t(backend));
//
//  sink->locked_backend()->set_file_collector(bl::sink::file::make_collector(
//    bl::keywords::target = "logs",
//    bl::keywords::max_size = 200,
//    bl::keywords::max_files = 2
//  ));
//
//   bl::core::get()->add_sink(sink);

//  bl::core::get()->set_filter(bl::trivial::severity >= bl::trivial::info);
}

}
