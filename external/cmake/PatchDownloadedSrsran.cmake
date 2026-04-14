if(NOT DEFINED SRSRAN_SRC_DIR)
  message(FATAL_ERROR "SRSRAN_SRC_DIR is required")
endif()

function(patch_file_contains path needle replacement description)
  file(READ "${path}" content)
  string(FIND "${content}" "${replacement}" replacement_pos)
  if(NOT replacement_pos EQUAL -1)
    message(STATUS "${description}: already applied")
    return()
  endif()

  string(FIND "${content}" "${needle}" needle_pos)
  if(needle_pos EQUAL -1)
    message(FATAL_ERROR "${description}: expected snippet not found in ${path}")
  endif()

  string(REPLACE "${needle}" "${replacement}" patched "${content}")
  file(WRITE "${path}" "${patched}")
  message(STATUS "${description}: applied")
endfunction()

set(fmt_core "${SRSRAN_SRC_DIR}/lib/include/srsran/srslog/bundled/fmt/core.h")
patch_file_contains(
  "${fmt_core}"
  [=[#include <cstring>
#include <functional>
#include <iterator>]=]
  [=[#include <cstring>
#include <functional>
#include <array>
#include <iterator>]=]
  "fmt <array> include fix")

set(srsran_cmake "${SRSRAN_SRC_DIR}/CMakeLists.txt")
patch_file_contains(
  "${srsran_cmake}"
  [=[# Add -Werror to C/C++ flags for newer compilers
if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5.0)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
endif()]=]
  [=[# Add -Werror to C/C++ flags for newer compilers
# Disabled for local GCC 12/aarch64 builds where vendored srsRAN emits warnings
# that are non-fatal in practice but stop the full LTESniffer build.
# if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5.0)
#   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
#   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
# endif()]=]
  "srsRAN Werror disable")
