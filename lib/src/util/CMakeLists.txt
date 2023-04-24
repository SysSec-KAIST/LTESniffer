 
file(GLOB SOURCES "*.cc")
add_library(falcon_util STATIC ${SOURCES})
target_compile_options(falcon_util PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)
install(
    TARGETS falcon_util
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})
