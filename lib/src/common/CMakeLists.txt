
# virtual target which is always treated as out-of-date on each build
# Note: a recompilation of depending targets is only triggered, if
#       "CurrentVersion.cc" is actually changed by the script "Version.cmake".
#       This happens only if the repos state has actually changed:
#           -
add_custom_target(check_git
    ALL
    BYPRODUCTS
        ${CMAKE_CURRENT_BINARY_DIR}/CurrentVersion.cc
    COMMENT "Checking version information an state of the git repository"
    COMMAND
        ${CMAKE_COMMAND}
        -DTHE_SOURCE_DIR=${CMAKE_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/Version.cmake
)

file(GLOB SOURCES "*.cc" "*.c")
add_library(falcon_common STATIC ${SOURCES} "${CMAKE_CURRENT_BINARY_DIR}/CurrentVersion.cc")
add_dependencies(falcon_common check_git)
target_compile_options(falcon_common PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)
install(
    TARGETS falcon_common
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})
