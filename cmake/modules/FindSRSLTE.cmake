 
# - Try to find srslte
#
# Once done this will define
#  SRSLTE_FOUND        - System has srslte
#  SRSLTE_INCLUDE_DIRS - The srslte include directories
#  SRSLTE_LIBRARIES    - The srslte libraries
#
# The following variables are used:
#  SRSLTE_DIR          - Environment variable giving srslte install directory
#  SRSLTE_SRCDIR       - Directory containing srslte sources
#  SRSLTE_BUILDDIR     - Directory containing srslte build

find_package(PkgConfig)
pkg_check_modules(PC_SRSLTE QUIET srslte)
set(SRSLTE_DEFINITIONS ${PC_SRSLTE_CFLAGS_OTHER})

FIND_PATH(
    SRSLTE_INCLUDE_DIRS
    NAMES   srslte/srslte.h
    HINTS   $ENV{SRSLTE_DIR}/include
            ${SRSLTE_SRCDIR}/srslte/include
            ${PC_SRSLTE_INCLUDEDIR}
            ${CMAKE_INSTALL_PREFIX}/include
    PATHS   /usr/local/include
            /usr/include
)

FIND_LIBRARY(
    SRSLTE_LIBRARY
    NAMES   srslte_common
    HINTS   $ENV{SRSLTE_DIR}/lib
            ${SRSLTE_BUILDDIR}/srslte/lib
            ${PC_SRSLTE_LIBDIR}
            ${CMAKE_INSTALL_PREFIX}/lib
            ${CMAKE_INSTALL_PREFIX}/lib64
    PATHS   /usr/local/lib
            /usr/local/lib64
            /usr/lib
            /usr/lib64
)

FIND_LIBRARY(
    SRSLTE_LIBRARY_RADIO
    NAMES   srslte_radio
    HINTS   $ENV{SRSLTE_DIR}/lib
            ${SRSLTE_BUILDDIR}/srslte/lib
            ${PC_SRSLTE_LIBDIR}
            ${CMAKE_INSTALL_PREFIX}/lib
            ${CMAKE_INSTALL_PREFIX}/lib64
    PATHS   /usr/local/lib
            /usr/local/lib64
            /usr/lib
            /usr/lib64
)


FIND_LIBRARY(
    SRSLTE_LIBRARY_UPPER
    NAMES   srslte_upper
    HINTS   $ENV{SRSLTE_DIR}/lib
            ${SRSLTE_BUILDDIR}/srslte/lib
            ${PC_SRSLTE_LIBDIR}
            ${CMAKE_INSTALL_PREFIX}/lib
            ${CMAKE_INSTALL_PREFIX}/lib64
    PATHS   /usr/local/lib
            /usr/local/lib64
            /usr/lib
            /usr/lib64
)
FIND_LIBRARY(
    SRSLTE_LIBRARY_ASN1
    NAMES   srslte_asn1
    HINTS   $ENV{SRSLTE_DIR}/lib
            ${SRSLTE_BUILDDIR}/srslte/lib
            ${PC_SRSLTE_LIBDIR}
            ${CMAKE_INSTALL_PREFIX}/lib
            ${CMAKE_INSTALL_PREFIX}/lib64
    PATHS   /usr/local/lib
            /usr/local/lib64
            /usr/lib
            /usr/lib64
)

FIND_LIBRARY(
    SRSLTE_LIBRARY_PHY
    NAMES   srslte_phy
    HINTS   $ENV{SRSLTE_DIR}/lib
            ${SRSLTE_BUILDDIR}/srslte/lib
            ${PC_SRSLTE_LIBDIR}
            ${CMAKE_INSTALL_PREFIX}/lib
            ${CMAKE_INSTALL_PREFIX}/lib64
    PATHS   /usr/local/lib
            /usr/local/lib64
            /usr/lib
            /usr/lib64
)

FIND_LIBRARY(
    SRSLTE_LIBRARY_RF
    NAMES   srslte_rf
    HINTS   $ENV{SRSLTE_DIR}/lib
            ${SRSLTE_BUILDDIR}/srslte/lib
            ${PC_SRSLTE_LIBDIR}
            ${CMAKE_INSTALL_PREFIX}/lib
            ${CMAKE_INSTALL_PREFIX}/lib64
    PATHS   /usr/local/lib
            /usr/local/lib64
            /usr/lib
            /usr/lib64
)

#FIND_LIBRARY(
#    SRSLTE_LIBRARY_RF_UTILS
#    NAMES   srslte_rf_utils
#    HINTS   $ENV{SRSLTE_DIR}/lib
#            ${SRSLTE_BUILDDIR}/srslte/lib
#            ${PC_SRSLTE_LIBDIR}
#            ${CMAKE_INSTALL_PREFIX}/lib
#            ${CMAKE_INSTALL_PREFIX}/lib64
#    PATHS   /usr/local/lib
#            /usr/local/lib64
#            /usr/lib
#            /usr/lib64
#)


IF(DEFINED SRSLTE_SRCDIR)
    set(SRSLTE_INCLUDE_DIRS ${SRSLTE_SRCDIR}/srslte
                            ${SRSLTE_SRCDIR}/cuhd
                            ${SRSLTE_SRCDIR}/common
                            ${SRSLTE_SRCDIR}/radio
                            ${SRSLTE_SRCDIR}/upper
                            ${SRSLTE_SRCDIR}/phy
                            ${SRSLTE_SRCDIR}/asn1)
ENDIF(DEFINED SRSLTE_SRCDIR)

#                            ${SRSLTE_LIBRARY_RF}
#                            ${SRSLTE_LIBRARY_RADIO}
set(SRSLTE_LIBRARIES        ${SRSLTE_LIBRARY}
                            ${SRSLTE_LIBRARY_RF_UTILS}
                            ${SRSLTE_LIBRARY_PHY}
                            ${SRSLTE_LIBRARY_UPPER}
                            ${SRSLTE_LIBRARY_ASN1}
)

if(SRSLTE_LIBRARY_RF)
    list(APPEND SRSLTE_LIBRARIES ${SRSLTE_LIBRARY_RF})
endif(SRSLTE_LIBRARY_RF)

if(SRSLTE_LIBRARY_RADIO)
    list(APPEND SRSLTE_LIBRARIES ${SRSLTE_LIBRARY_RADIO})
endif(SRSLTE_LIBRARY_RADIO)

message(STATUS "SRSLTE LIBRARIES are: " ${SRSLTE_LIBRARIES})
message(STATUS "SRSLTE INCLUDE DIRS: " ${SRSLTE_INCLUDE_DIRS})

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(SRSLTE DEFAULT_MSG SRSLTE_LIBRARIES SRSLTE_INCLUDE_DIRS)
MARK_AS_ADVANCED(SRSLTE_LIBRARIES SRSLTE_INCLUDE_DIRS)
