 
# - Try to find srslte
#
# Once done this will define
#  CMNALIB_FOUND        - System has srslte
#  CMNALIB_INCLUDE_DIRS - The srslte include directories
#  CMNALIB_LIBRARIES    - The srslte libraries
#
# The following variables are used:
#  CMNALIB_DIR          - Environment variable giving srslte install directory
#  CMNALIB_SRCDIR       - Directory containing srslte sources
#  CMNALIB_BUILDDIR     - Directory containing srslte build

find_package(PkgConfig)
pkg_check_modules(PC_CMNALIB QUIET cmnalib)
set(CMNALIB_DEFINITIONS ${PC_CMNALIB_CFLAGS_OTHER})

#FIND_PATH(
#    CMNALIB_INCLUDE_DIRS
#    NAMES   cmnalib/cmnalib.h
#    HINTS   $ENV{CMNALIB_DIR}/include
#            ${CMNALIB_SRCDIR}/cmnalib/include
#            ${PC_CMNALIB_INCLUDEDIR}
#            ${CMAKE_INSTALL_PREFIX}/include
#    PATHS   /usr/local/include
#            /usr/include
#)

FIND_LIBRARY(
    CMNALIB_LIBRARY
    NAMES   cmnalib
    HINTS   $ENV{CMNALIB_DIR}/lib
            ${CMNALIB_BUILDDIR}/cmnalib/lib
            ${PC_CMNALIB_LIBDIR}
            ${CMAKE_INSTALL_PREFIX}/lib
            ${CMAKE_INSTALL_PREFIX}/lib64
    PATHS   /usr/local/lib
            /usr/local/lib64
            /usr/lib
            /usr/lib64
)

IF(DEFINED CMNALIB_SRCDIR)
    set(CMNALIB_INCLUDE_DIRS ${CMNALIB_SRCDIR})                            
                            
ENDIF(DEFINED CMNALIB_SRCDIR)

SET(CMNALIB_LIBRARIES   ${CMNALIB_LIBRARY})

message(STATUS "CMNALIB LIBRARIES: " ${CMNALIB_LIBRARIES})
#message(STATUS "CMNALIB INCLUDE DIRS: " ${CMNALIB_INCLUDE_DIRS})

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CMNALIB DEFAULT_MSG CMNALIB_LIBRARIES) 
#CMNALIB_INCLUDE_DIRS
MARK_AS_ADVANCED(CMNALIB_LIBRARIES)
#CMNALIB_INCLUDE_DIRS
