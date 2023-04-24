
# Cmake script to generate/update version strings during compilation
# to reflect the state of the git repository (tag, branch, commit, modifications)

# Example call for this script from cmake:
#       cmake -DTHE_SOURCE_DIR=${CMAKE_SOURCE_DIR} -P ${CMAKE_CURRENT_SOURCE_DIR}/Version.cmake

execute_process(
    COMMAND git log --pretty=format:'%h' -n 1
    WORKING_DIRECTORY ${THE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_REV
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# Check if git version info is available or
# if the source was downloaded as zip without git.
if ("${GIT_REV}" STREQUAL "")
    set(GIT_REV "N/A")
    set(GIT_DIRTY "")
    set(GIT_TAG "N/A")
    set(GIT_BRANCH "N/A")
else()
    execute_process(
        COMMAND bash -c "git diff --quiet --exit-code || echo +"
        WORKING_DIRECTORY ${THE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_DIRTY
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    execute_process(
        COMMAND git describe --exact-match --tags
        WORKING_DIRECTORY ${THE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_TAG
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    execute_process(
        COMMAND git rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY ${THE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )

    string(SUBSTRING "${GIT_REV}" 1 7 GIT_REV)
endif()

# Generate a C++ file with version strings
set(VERSION
"
#include \"falcon/common/Version.h\"

const std::string Version::GIT_REV=\"${GIT_REV}\";
const std::string Version::GIT_DIRTY=\"${GIT_DIRTY}\";
const std::string Version::GIT_TAG=\"${GIT_TAG}\";
const std::string Version::GIT_BRANCH=\"${GIT_BRANCH}\";
"
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/CurrentVersion.cc")
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/CurrentVersion.cc" VERSION_PREV)
else()
    set(VERSION_PREV "--EMPTY--")
endif()

if (NOT "${VERSION}" STREQUAL "${VERSION_PREV}")
    message("Updating CurrentVersion.cc")
    file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/CurrentVersion.cc" "${VERSION}")
else()
    message("CurrentVersion.cc is already up to date")
endif()
