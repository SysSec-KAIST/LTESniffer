
add_subdirectory(falcon_rf)
add_subdirectory(falcon_ue)
add_subdirectory(falcon_phch)

set(falcon_objs
  $<TARGET_OBJECTS:falcon_ue>
  $<TARGET_OBJECTS:falcon_phch>
)

add_library(falcon_phy STATIC ${falcon_objs})
target_link_libraries(falcon_phy
  ${SRSLTE_LIBRARIES}
  ${FFT_LIBRARIES}
  pthread
  ${Boost_LIBRARIES})
install(
  TARGETS falcon_phy
  ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})
