
add_subdirectory(src)
add_subdirectory(test)

########################################################################
# Install library headers
########################################################################
install(  DIRECTORY include/
          DESTINATION "${INCLUDE_DIR}"
          FILES_MATCHING PATTERN "*.h" )

########################################################################
# Install libs
########################################################################
# nested install targets are not supported by old Cmake on Ubuntu 18
#install(
#    TARGETS
#        falcon_common
#        falcon_meas
#        falcon_phy
#        falcon_prof
#        falcon_util
#    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
#    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
#    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})
