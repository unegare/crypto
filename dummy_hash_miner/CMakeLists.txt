cmake_minimum_required(VERSION 3.11)

set(CMAKE_CXX_COMPILER g++-10)

#add_definitions(-DBOOST_LOG_DYN_LINK)

set(Boost_USE_STATIC_LIBS ON)

project(main)

find_package(Boost 1.70 COMPONENTS system log thread log_setup REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include/ ${Boost_INCLUDE_DIR})

set(SOURCES_task ${CMAKE_SOURCE_DIR}/src/task.cpp)
set(HEADERS_task ${CMAKE_SOURCE_DIR}/include/task.h)

set(SOURCES_Message ${CMAKE_SOURCE_DIR}/src/Message.cpp)
set(HEADERS_Message ${CMAKE_SOURCE_DIR}/include/Message.h)

set(SOURCES_sighandlers ${CMAKE_SOURCE_DIR}/src/sighandlers.cpp)
set(HEADERS_sighandlers ${CMAKE_SOURCE_DIR}/include/sighandlers.h)

set(SOURCES_log ${CMAKE_SOURCE_DIR}/src/log.cpp)
set(HEADERS_log ${CMAKE_SOURCE_DIR}/include/log.h)

add_library(Message ${SOURCES_Message} ${HEADERS_Message})
set_property(TARGET Message PROPERTY CXX_STANDARD 20)

add_library(sighandlers ${SOURCES_sighandlers} ${HEADERS_sighandlers})
set_property(TARGET sighandlers PROPERTY CXX_STANDARD 20)

add_library(log ${SOURCES_log} ${HEADERS_log})
set_property(TARGET log PROPERTY CXX_STANDARD 20)
#target_link_libraries(log PRIVATE ${Boost_LOG_LIBRARY})
target_link_libraries(log PUBLIC Boost::log Boost::log_setup)

add_library(task ${SOURCES_task} ${HEADERS_task})
set_property(TARGET task PROPERTY CXX_STANDARD 20)
target_link_libraries(task PUBLIC Message sighandlers log)

add_executable(${CMAKE_PROJECT_NAME} ${CMAKE_SOURCE_DIR}/src/main.cpp ${HEADERS_task} ${HEADERS_Message})
#target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include/)
set_property(TARGET ${CMAKE_PROJECT_NAME} PROPERTY CXX_STANDARD 20)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE OpenSSL::SSL)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Threads::Threads)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE task)
