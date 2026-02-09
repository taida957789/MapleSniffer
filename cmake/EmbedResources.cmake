# EmbedResources.cmake
# Converts files in a directory into C++ header with embedded byte arrays.
#
# Usage:
#   embed_resources(
#     INPUT_DIR  "${CMAKE_SOURCE_DIR}/frontend/dist"
#     OUTPUT_DIR "${CMAKE_BINARY_DIR}/generated"
#     HEADER     "web_resources.h"
#   )

function(embed_resources)
    cmake_parse_arguments(ER "" "INPUT_DIR;OUTPUT_DIR;HEADER" "" ${ARGN})

    if(NOT EXISTS "${ER_INPUT_DIR}")
        message(STATUS "[EmbedResources] Input dir not found: ${ER_INPUT_DIR} — skipping resource embedding.")
        return()
    endif()

    file(MAKE_DIRECTORY "${ER_OUTPUT_DIR}")

    file(GLOB_RECURSE _all_files RELATIVE "${ER_INPUT_DIR}" "${ER_INPUT_DIR}/*")

    if(NOT _all_files)
        message(STATUS "[EmbedResources] No files found in ${ER_INPUT_DIR} — skipping.")
        return()
    endif()

    set(_header_content "#pragma once\n")
    string(APPEND _header_content "#include <unordered_map>\n")
    string(APPEND _header_content "#include <string>\n")
    string(APPEND _header_content "#include <utility>\n")
    string(APPEND _header_content "#include <cstddef>\n\n")

    set(_map_entries "")
    set(_array_index 0)

    foreach(_file ${_all_files})
        set(_full_path "${ER_INPUT_DIR}/${_file}")

        # Create a valid C identifier from the file path
        string(REGEX REPLACE "[^a-zA-Z0-9]" "_" _var_name "${_file}")
        set(_var_name "res_${_array_index}_${_var_name}")

        # Read file as hex
        file(READ "${_full_path}" _hex_content HEX)
        string(LENGTH "${_hex_content}" _hex_len)

        if(_hex_len EQUAL 0)
            math(EXPR _array_index "${_array_index} + 1")
            continue()
        endif()

        # Convert hex string to comma-separated byte array
        set(_bytes "")
        set(_i 0)
        while(_i LESS _hex_len)
            string(SUBSTRING "${_hex_content}" ${_i} 2 _byte)
            if(_bytes)
                string(APPEND _bytes ",0x${_byte}")
            else()
                set(_bytes "0x${_byte}")
            endif()
            math(EXPR _i "${_i} + 2")

            # Add newline every 32 bytes for readability
            math(EXPR _mod "(${_i} / 2) % 32")
            if(_mod EQUAL 0 AND _i LESS _hex_len)
                string(APPEND _bytes "\n    ")
            endif()
        endwhile()

        math(EXPR _byte_count "${_hex_len} / 2")

        string(APPEND _header_content "static const unsigned char ${_var_name}[] = {\n    ${_bytes}\n};\n\n")

        # URL path: forward slashes, leading /
        string(REPLACE "\\" "/" _url_path "${_file}")
        set(_url_path "/${_url_path}")

        string(APPEND _map_entries "    {\"${_url_path}\", {${_var_name}, ${_byte_count}}},\n")

        math(EXPR _array_index "${_array_index} + 1")
    endforeach()

    string(APPEND _header_content "inline const std::unordered_map<std::string, std::pair<const unsigned char*, size_t>> web_resources = {\n")
    string(APPEND _header_content "${_map_entries}")
    string(APPEND _header_content "};\n")

    file(WRITE "${ER_OUTPUT_DIR}/${ER_HEADER}" "${_header_content}")
    message(STATUS "[EmbedResources] Generated ${ER_HEADER} with ${_array_index} files.")
endfunction()
