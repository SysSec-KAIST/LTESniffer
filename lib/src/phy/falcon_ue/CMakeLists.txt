 
file(GLOB SOURCES "*.c" "*.cc")
add_library(falcon_ue OBJECT ${SOURCES})

if(DEFINED MAX_RECURSION_DEPTH)
    target_compile_definitions(falcon_ue PRIVATE -DMAX_RECURSION_DEPTH=${MAX_RECURSION_DEPTH})
endif()
if(DEFINED DCI_DISAMBIGUATION_DEPTH)
    target_compile_definitions(falcon_ue PRIVATE -DDCI_DISAMBIGUATION_DEPTH=${DCI_DISAMBIGUATION_DEPTH})
endif()
