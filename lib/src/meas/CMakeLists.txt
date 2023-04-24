 
file(GLOB SOURCES "*.cc" "*.c")
add_library(falcon_meas STATIC ${SOURCES})
target_compile_options(falcon_meas PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

target_link_libraries(falcon_meas
  falcon_common
  falcon_prof
  pthread
  ${CMNALIB_LIBRARIES}
  ${SRSLTE_LIBRARIES})
install(
  TARGETS falcon_meas
  ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})
