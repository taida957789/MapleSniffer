cmake_minimum_required(VERSION 3.21)

if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project(MapleSniffer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/EHsc)
    add_compile_definitions(NOMINMAX)
endif()

# --- vcpkg dependencies ---
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# --- Npcap SDK (local) ---
set(NPCAP_SDK_DIR "${CMAKE_SOURCE_DIR}/third_party/npcap-sdk")
set(NPCAP_INCLUDE_DIR "${NPCAP_SDK_DIR}/Include")
set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")

# --- Saucer (webview) ---
include(FetchContent)

# Patch PackageProject to guard duplicate ALIAS targets (CMake 3.31+ / vcpkg compat)
FetchContent_Declare(PackageProject
    GIT_REPOSITORY "https://github.com/TheLartians/PackageProject.cmake"
    GIT_TAG        v1.13.0
    PATCH_COMMAND  ${CMAKE_COMMAND} -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/patch_packageproject.cmake"
)

FetchContent_Declare(saucer
    GIT_REPOSITORY "https://github.com/saucer/saucer"
    GIT_TAG        v8.0.4
)
FetchContent_MakeAvailable(saucer)

# --- Sources ---
set(SOURCES
    src/main.cpp
    src/capture/capture.cpp
    src/protocol/tcp_reasm.cpp
    src/protocol/protocol.cpp
    src/protocol/maple_aes.cpp
    src/protocol/maple_stream.cpp
    src/app/app.cpp
)

add_executable(MapleSniffer ${SOURCES} app.rc)

# --- Embed frontend into binary (must come after add_executable) ---
saucer_embed("frontend/dist" TARGET MapleSniffer)

target_include_directories(MapleSniffer PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${NPCAP_INCLUDE_DIR}
)

target_link_libraries(MapleSniffer PRIVATE
    ${NPCAP_LIB_DIR}/wpcap.lib
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
    saucer::saucer
    saucer::embedded
)
