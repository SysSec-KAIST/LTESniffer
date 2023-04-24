 
file(GLOB SOURCES "*.cc" "*.c")
add_library(falcon_prof STATIC ${SOURCES})
target_compile_options(falcon_prof PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)
install(
    TARGETS falcon_prof
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})
