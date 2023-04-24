file(GLOB SOURCES "*.cc" "*.c")

add_library(DL_Sniffer_lib STATIC ${SOURCES})

target_compile_options(DL_Sniffer_lib PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

target_link_libraries(DL_Sniffer_lib
    pthread
    srsran_phy
    srsran_asn1
    s1ap_asn1
    rrc_asn1
    asn1_utils
    falcon_phy
    ${FFT_LIBRARIES}
    ${Boost_LIBRARIES}
    ${SRSRAN_LIBRARIES})

install(
    TARGETS DL_Sniffer_lib
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})
