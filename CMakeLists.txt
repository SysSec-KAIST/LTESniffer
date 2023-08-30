cmake_minimum_required (VERSION 2.8.11)

#######################################################################
#   INSTALL TARGET for make install
#######################################################################
#SET(CMAKE_INSTALL_PREFIX /usr/local)

#message("CIP = ${CMAKE_INSTALL_PREFIX} (should be /usr/local")
project (DL_Sniffer)

#set (CMAKE_INSTALL_PREFIX /usr/local)

#message("CIP = ${CMAKE_INSTALL_PREFIX} (should be /usr/local")

#######################################################################
#   OPTIONS:
#######################################################################

#option(ENABLE_SRSUE    "Build srsUE application"                  ON)
#option(ENABLE_SRSENB   "Build srsENB application"                 ON)
#option(ENABLE_SRSEPC   "Build srsEPC application"                 ON)
option(DISABLE_SIMD    "disable simd instructions"                OFF)

option(FORCE_SUBPROJECT_CMNALIB "Download and build CMNALIB"      OFF)
option(FORCE_SUBPROJECT_SRSRAN  "Download and build SRSRAN"       OFF)

option(ENABLE_GUI      "Enable GUI (using srsGUI)"                ON)
option(ENABLE_UHD      "Enable UHD"                               ON)
option(ENABLE_BLADERF  "Enable BladeRF"                           ON)
option(ENABLE_SOAPYSDR "Enable SoapySDR"                          ON)
#option(ENABLE_HARDSIM  "Enable support for SIM cards"             ON)

option(BUILD_STATIC    "Attempt to statically link external deps" OFF)
#option(RPATH           "Enable RPATH"                             OFF)
option(ENABLE_ASAN     "Enable gcc/clang address sanitizer"       OFF)
option(ENABLE_MSAN     "Enable clang memory sanitizer"            OFF)
option(ENABLE_TIDY     "Enable clang tidy"                        OFF)

#option(USE_LTE_RATES   "Use standard LTE sampling rates"          OFF)

set(GCC_ARCH native CACHE STRING "GCC compile for specific architecture.")

###########################################################################


########################################################################
# Extra options
########################################################################

if(NOT DEFINED MAX_RECURSION_DEPTH)
    set(MAX_RECURSION_DEPTH 99)
endif()
#add_definitions(-DMAX_RECURSION_DEPTH=${MAX_RECURSION_DEPTH})
########################################################################


if(NOT CMAKE_BUILD_TYPE)
  #    set(CMAKE_BUILD_TYPE Release)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
  message(STATUS "Build type not specified: defaulting to ${CMAKE_BUILD_TYPE}.")
endif(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING "")

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/modules")

########################################################################
# Dependencies
########################################################################

# Check for CMNAlib in system.

find_package(CMNALIB)
if(CMNALIB_FOUND AND NOT FORCE_SUBPROJECT_CMNALIB)
  include_directories(${CMNALIB_INCLUDE_DIRS})
  link_directories(${CMNALIB_LIBRARY_DIRS})
else(CMNALIB_FOUND AND NOT FORCE_SUBPROJECT_CMNALIB)
  message("Download CMNALIB as a subproject and build it.")

  # Download and unpack cmnalib at configure time
  configure_file(external/cmake/cmnalib.CMakeLists.txt.in cmnalib-download/CMakeLists.txt)
  execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/cmnalib-download" )
  execute_process(COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/cmnalib-download" )

  include_directories("${CMAKE_BINARY_DIR}/cmnalib-src/src/cmnalib/include")

  # Add cmnalib directly to our build.
  add_subdirectory("${CMAKE_BINARY_DIR}/cmnalib-src"
    "${CMAKE_BINARY_DIR}/cmnalib-build")
  set(CMNALIB_LIBRARY cmnalib)
  set(CMNALIB_LIBRARIES ${CMNALIB_LIBRARY})
endif(CMNALIB_FOUND AND NOT FORCE_SUBPROJECT_CMNALIB)

message("CMNALIB_LIBRARY: " ${CMNALIB_LIBRARY})
message("CMNALIB_LIBRARIES: " ${CMNALIB_LIBRARIES})

# cmnalib also needs glib:

INCLUDE(FindPkgConfig)
pkg_check_modules(GLIB2   REQUIRED  glib-2.0)

include_directories(${GLIB2_INCLUDE_DIRS})
#link_directories(${GLIB2_LIBRARY_DIRS})

############################################

############################################


# Threads
find_package(Threads REQUIRED)

#FFT
find_package(MKL)
if(MKL_FOUND)
  include_directories(${MKL_INCLUDE_DIRS})
  link_directories(${MKL_LIBRARY_DIRS})
  set(FFT_LIBRARIES "${MKL_STATIC_LIBRARIES}") # Static by default
else(MKL_FOUND)
  find_package(FFTW3F REQUIRED)
  if(FFTW3F_FOUND)
    include_directories(${FFTW3F_INCLUDE_DIRS})
    link_directories(${FFTW3F_LIBRARY_DIRS})
    if(BUILD_STATIC)
      set(FFT_LIBRARIES "${FFTW3F_STATIC_LIBRARIES}")
    else(BUILD_STATIC)
      set(FFT_LIBRARIES "${FFTW3F_LIBRARIES}")
    endif(BUILD_STATIC)
    message(STATUS "FFT_LIBRARIES: " ${FFT_LIBRARIES})
  endif(FFTW3F_FOUND)
endif(MKL_FOUND)


# UHD
if(ENABLE_UHD)
  find_package(UHD)
  if(UHD_FOUND)
    include_directories(${UHD_INCLUDE_DIRS})
    link_directories(${UHD_LIBRARY_DIRS})
  endif(UHD_FOUND)
endif(ENABLE_UHD)

# BladeRF
if(ENABLE_BLADERF)
  find_package(bladeRF)
  if(BLADERF_FOUND)
    include_directories(${BLADERF_INCLUDE_DIRS})
    link_directories(${BLADERF_LIBRARY_DIRS})
  endif(BLADERF_FOUND)
endif(ENABLE_BLADERF)

# Soapy
if(ENABLE_SOAPYSDR)
  find_package(SoapySDR)
  if(SOAPYSDR_FOUND)
    include_directories(${SOAPYSDR_INCLUDE_DIRS})
    link_directories(${SOAPYSDR_LIBRARY_DIRS})
  endif(SOAPYSDR_FOUND)
endif(ENABLE_SOAPYSDR)

if(BLADERF_FOUND OR UHD_FOUND OR SOAPYSDR_FOUND)
  set(RF_FOUND TRUE CACHE INTERNAL "RF frontend found")
else(BLADERF_FOUND OR UHD_FOUND OR SOAPYSDR_FOUND)
  set(RF_FOUND FALSE CACHE INTERNAL "RF frontend found")
  add_definitions(-DDISABLE_RF)
endif(BLADERF_FOUND OR UHD_FOUND OR SOAPYSDR_FOUND)

#####################################################
find_package(SRSRAN)
if(SRSRAN_FOUND AND NOT FORCE_SUBPROJECT_SRSRAN)
  include_directories(${SRSLTE_INCLUDE_DIRS})
  link_directories(${SRSLTE_LIBRARY_DIRS})
else(SRSRAN_FOUND AND NOT FORCE_SUBPROJECT_SRSRAN)

  message("Download SRSRAN as a subproject and build it.")

  # Download and unpack srsRAN at configure time
  file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/srsRAN-src")
  file(COPY "${CMAKE_SOURCE_DIR}/srsRAN_4G_mirror/" DESTINATION "${CMAKE_BINARY_DIR}/srsRAN-src")

  configure_file(external/cmake/srsRAN.CMakeLists.txt.in srsRAN-download/CMakeLists.txt)
  execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/srsRAN-download" )
  execute_process(COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/srsRAN-download" )

  include_directories("${CMAKE_BINARY_DIR}/srsRAN-build/lib/include")
  include_directories("${CMAKE_BINARY_DIR}/srsRAN-src/lib/include")
  include_directories("${CMAKE_BINARY_DIR}/srsRAN-src/")
  # let the compiler find included files from subdirectories
  include_directories(".")

  # Add srsRAN directly to our build.
  add_subdirectory("${CMAKE_BINARY_DIR}/srsRAN-src"
    "${CMAKE_BINARY_DIR}/srsRAN-build")

  set(SRSRAN_LIBRARY_RF srsran_rf)
  set(SRSRAN_LIBRARY srsran_common)
  set(SRSRAN_LIBRARY_PHY srsran_phy)
  set(SRSRAN_LIBRARY_RADIO srsran_radio)
  set(SRSRAN_LIBRARY_ASN1 srsran_asn1)
  set(SRSRAN_LIBRARY_GTPU srsran_gtpu)
  set(SRSRAN_LIBRARY_MAC srsran_mac)
  set(SRSRAN_LIBRARY_PDCP srsran_pdcp)
  set(SRSRAN_LIBRARY_RLC srsran_rlc)
  # set(SRSRAN_LIBRARY_SRSLOG srsran_srslog)
  # set(SRSRAN_LIBRARY_SUPPORT srsran_support)
  # set(SRSRAN_LIBRARY_SYSTEM srsran_system)
  #    ${SRSRAN_LIBRARY_RF}
  #    ${SRSRAN_LIBRARY_RF_UTILS}
  #    ${SRSRAN_LIBRARY_RADIO}
  set(SRSRAN_LIBRARIES
    ${SRSRAN_LIBRARY}
    ${SRSRAN_LIBRARY_PHY}
    ${SRSRAN_LIBRARY_ASN1}
    ${SRSRAN_LIBRARY_GTPU}
    ${SRSRAN_LIBRARY_MAC}
    ${SRSRAN_LIBRARY_PDCP}
    ${SRSRAN_LIBRARY_RLC}
    # ${SRSRAN_LIBRARY_SRSLOG}
    # ${SRSRAN_LIBRARY_SUPPORT}
    # ${SRSRAN_LIBRARY_SYSTEM}
  )
  if(RF_FOUND)
    list(APPEND SRSRAN_LIBRARIES ${SRSRAN_LIBRARY_RF} ${SRSRAN_LIBRARY_RADIO})
  endif(RF_FOUND)

endif(SRSRAN_FOUND AND NOT FORCE_SUBPROJECT_SRSRAN)

message("SRSRAN_LIBRARIES: " ${SRSRAN_LIBRARIES})
#####################################################

# Boost
#if(ENABLE_SRSUE OR ENABLE_SRSENB OR ENABLE_SRSEPC)
if(BUILD_STATIC)
  set(Boost_USE_STATIC_LIBS ON)
endif(BUILD_STATIC)

set(BOOST_REQUIRED_COMPONENTS
  program_options
  system
  thread
  )
if(UNIX AND EXISTS "/usr/lib64")
  list(APPEND BOOST_LIBRARYDIR "/usr/lib64") #fedora 64-bit fix
endif(UNIX AND EXISTS "/usr/lib64")
set(Boost_ADDITIONAL_VERSIONS
  "1.35.0" "1.35" "1.36.0" "1.36" "1.37.0" "1.37" "1.38.0" "1.38" "1.39.0" "1.39"
  "1.40.0" "1.40" "1.41.0" "1.41" "1.42.0" "1.42" "1.43.0" "1.43" "1.44.0" "1.44"
  "1.45.0" "1.45" "1.46.0" "1.46" "1.47.0" "1.47" "1.48.0" "1.48" "1.49.0" "1.49"
  "1.50.0" "1.50" "1.51.0" "1.51" "1.52.0" "1.52" "1.53.0" "1.53" "1.54.0" "1.54"
  "1.55.0" "1.55" "1.56.0" "1.56" "1.57.0" "1.57" "1.58.0" "1.58" "1.59.0" "1.59"
  "1.60.0" "1.60" "1.61.0" "1.61" "1.62.0" "1.62" "1.63.0" "1.63" "1.64.0" "1.64"
  "1.65.0" "1.65" "1.66.0" "1.66" "1.67.0" "1.67" "1.68.0" "1.68" "1.69.0" "1.69"
  )
find_package(Boost "1.35" COMPONENTS ${BOOST_REQUIRED_COMPONENTS})

#endif(ENABLE_SRSUE OR ENABLE_SRSENB OR ENABLE_SRSEPC)

########################################################################
# Compiler specific setup
########################################################################
macro(ADD_CXX_COMPILER_FLAG_IF_AVAILABLE flag have)
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag(${flag} ${have})
  if(${have})
    add_definitions(${flag})
  endif(${have})
endmacro(ADD_CXX_COMPILER_FLAG_IF_AVAILABLE)

#ADD_CXX_COMPILER_FLAG_IF_AVAILABLE("-Werror=incompatible-pointer-types" HAVE_ERROR_INCOMPATIBLE)

if(CMAKE_C_COMPILER_ID MATCHES "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  message("MARCH - FLAGS: ${GCC_ARCH}")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=${GCC_ARCH} -Wall -Wno-comment -Wno-write-strings -Winline -Wno-unused-result -Wformat -Wmissing-field-initializers -Wtype-limits -std=c99 -D_GNU_SOURCE")

  find_package(SSE) # evaluation comes later

  if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0 -DDEBUG_MODE -DBUILD_TYPE_DEBUG")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb -O0 -DDEBUG_MODE -DBUILD_TYPE_DEBUG")
  else(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    if(${CMAKE_BUILD_TYPE} STREQUAL "RelWithDebInfo")
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -DBUILD_TYPE_RELWITHDEBINFO")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb -DBUILD_TYPE_RELWITHDEBINFO")
    else(${CMAKE_BUILD_TYPE} STREQUAL "RelWithDebInfo")
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -fno-trapping-math -fno-math-errno -DBUILD_TYPE_RELEASE")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fno-trapping-math -fno-math-errno -DBUILD_TYPE_RELEASE")
    endif(${CMAKE_BUILD_TYPE} STREQUAL "RelWithDebInfo")
  endif(${CMAKE_BUILD_TYPE} STREQUAL "Debug")

  if (USE_LTE_RATES)
    message(STATUS "Using standard LTE sampling rates")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DFORCE_STANDARD_RATE")
  endif (USE_LTE_RATES)

  #find_package(SSE)  # moved upwards before BUILD_TYPE-specific flags. -> AVX512 detection/test code gets subject of O3 optimization -> reports availability even if not present
  if (HAVE_AVX2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpmath=sse -mavx2 -DLV_HAVE_AVX2 -DLV_HAVE_AVX -DLV_HAVE_SSE")
  else (HAVE_AVX2)
    if(HAVE_AVX)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpmath=sse -mavx -DLV_HAVE_AVX -DLV_HAVE_SSE")
    elseif(HAVE_SSE)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpmath=sse -msse4.1 -DLV_HAVE_SSE")
    endif(HAVE_AVX)
  endif (HAVE_AVX2)

  if (HAVE_FMA)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfma -DLV_HAVE_FMA")
  endif (HAVE_FMA)

  if (HAVE_AVX512)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx512f -mavx512cd -DLV_HAVE_AVX512")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx512f -mavx512cd -DLV_HAVE_AVX512")
  endif(HAVE_AVX512)

  if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    if(HAVE_SSE)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast -funroll-loops")
    endif(HAVE_SSE)
  endif(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Debug")

  if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")

    set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -mfpu=neon -march=native -DIS_ARM -DHAVE_NEON")
    message(STATUS "have ARM")
    set(HAVE_NEON "True")
  else(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
    set(HAVE_NEON "False")
  endif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
  set(CMAKE_REQUIRED_FLAGS ${CMAKE_C_FLAGS})

  if(NOT HAVE_SSE AND NOT HAVE_NEON AND NOT DISABLE_SIMD)
    message(FATAL_ERROR "no SIMD instructions found")
  endif(NOT HAVE_SSE AND NOT HAVE_NEON AND NOT DISABLE_SIMD)

  if(NOT WIN32)
    ADD_CXX_COMPILER_FLAG_IF_AVAILABLE(-fvisibility=hidden HAVE_VISIBILITY_HIDDEN)
  endif(NOT WIN32)

  if (ENABLE_ASAN AND ENABLE_MSAN)
    message(FATAL_ERROR "ASAN and MSAN cannot be enabled at the same time.")
  endif (ENABLE_ASAN AND ENABLE_MSAN)

  if (ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  endif (ENABLE_ASAN)

  if (ENABLE_MSAN AND CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=memory -fno-omit-frame-pointer -fPIE -pie")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=memory -fno-omit-frame-pointer -fPIE -pie")
  endif (ENABLE_MSAN AND CMAKE_C_COMPILER_ID MATCHES "Clang")

endif(CMAKE_C_COMPILER_ID MATCHES "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  # The following is needed for weak linking to work under OS X
  set(CMAKE_SHARED_LINKER_FLAGS "-undefined dynamic_lookup")
endif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

message(STATUS "CMAKE_C_FLAGS is ${CMAKE_C_FLAGS}")
message(STATUS "CMAKE_CXX_FLAGS is ${CMAKE_CXX_FLAGS}")

########################################################################
# Add -fPIC property to all targets
########################################################################
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

########################################################################
# Install Dirs
########################################################################
if (NOT CMAKE_INSTALL_LIBDIR)
  include(GNUInstallDirs)
endif (NOT CMAKE_INSTALL_LIBDIR)

set(RUNTIME_PATH bin)       # PATH to usr/local/bin     for install
set(INCLUDE_DIR include)    # PATH to usr/local/include for install

########################################################################
# Add general includes and dependencies
########################################################################
include_directories(${PROJECT_BINARY_DIR}/lib/include)
include_directories(${PROJECT_SOURCE_DIR}/lib/include)
include_directories(${PROJECT_SOURCE_DIR}/src)  # for cross includes of top-level applications
include_directories(${PROJECT_SOURCE_DIR}/lib)
########################################################################
# Add the subdirectories
########################################################################

# Remove _GNU_SOURCE definition for the next targets due to issues with clang code model in Qt Creator
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -U_GNU_SOURCE")

add_subdirectory(lib)
add_subdirectory(src)
