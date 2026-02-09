cmake_minimum_required(VERSION 3.15)

if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project(MapleAuto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/EHsc)
endif()

# --- vcpkg dependencies ---
find_package(nlohmann_json CONFIG REQUIRED)

# --- Npcap SDK (local) ---
set(NPCAP_SDK_DIR "${CMAKE_SOURCE_DIR}/third_party/npcap-sdk")
set(NPCAP_INCLUDE_DIR "${NPCAP_SDK_DIR}/Include")
set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")

# --- Embed frontend resources ---
include(cmake/EmbedResources.cmake)
embed_resources(
    INPUT_DIR  "${CMAKE_SOURCE_DIR}/frontend/dist"
    OUTPUT_DIR "${CMAKE_BINARY_DIR}/generated"
    HEADER     "web_resources.h"
)

# --- Sources ---
set(SOURCES
    src/main.cpp
    src/capture/capture.cpp
    src/protocol/protocol.cpp
    src/server/server.cpp
    src/input/input.cpp
)

add_executable(MapleAuto ${SOURCES})

target_include_directories(MapleAuto PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}/generated
    ${NPCAP_INCLUDE_DIR}
)

target_link_libraries(MapleAuto PRIVATE
    ${NPCAP_LIB_DIR}/wpcap.lib
    nlohmann_json::nlohmann_json
)

# cpp-httplib (header-only, included directly in src/server/)
# needs ws2_32 and additional Windows networking libs
if(WIN32)
    target_link_libraries(MapleAuto PRIVATE ws2_32 crypt32)
endif()
