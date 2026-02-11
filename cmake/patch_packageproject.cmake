# Patch PackageProject.cmake to guard ALIAS target creation.
# CMake 3.31+ errors on duplicate ALIAS targets.
# saucer's dependencies (lockpp, coco, etc.) create aliases themselves,
# then packageProject() tries to re-create them, causing a fatal error.
#
# This script adds an `if(NOT TARGET ...)` guard around the add_library(ALIAS) call.

file(READ "CMakeLists.txt" content)

# Check if already patched (idempotent)
string(FIND "${content}" "NOT TARGET" idx)
if(NOT idx EQUAL -1)
    return()
endif()

# The original line (indented with 4 spaces):
#     add_library(${PROJECT_NAMESPACE}${PROJECT_NAME} ALIAS ${PROJECT_NAME})
# Replace with guarded version:
set(search [=[  if(DEFINED PROJECT_NAMESPACE)
    if(PROJECT_CPACK)
      set(CPACK_PACKAGE_NAMESPACE ${PROJECT_NAMESPACE})
    endif()
    set(PROJECT_NAMESPACE ${PROJECT_NAMESPACE}::)
    add_library(${PROJECT_NAMESPACE}${PROJECT_NAME} ALIAS ${PROJECT_NAME})
  endif()]=])

set(replace [=[  if(DEFINED PROJECT_NAMESPACE)
    if(PROJECT_CPACK)
      set(CPACK_PACKAGE_NAMESPACE ${PROJECT_NAMESPACE})
    endif()
    set(PROJECT_NAMESPACE ${PROJECT_NAMESPACE}::)
    if(NOT TARGET ${PROJECT_NAMESPACE}${PROJECT_NAME})
      add_library(${PROJECT_NAMESPACE}${PROJECT_NAME} ALIAS ${PROJECT_NAME})
    endif()
  endif()]=])

string(REPLACE "${search}" "${replace}" content "${content}")
file(WRITE "CMakeLists.txt" "${content}")
message(STATUS "[patch] PackageProject.cmake patched for ALIAS guard")
