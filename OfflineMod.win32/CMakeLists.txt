configure_file("${CMAKE_CURRENT_LIST_DIR}/serverconfig.h.cmake" "${CMAKE_CURRENT_BINARY_DIR}/generated/serverconfig.h")

add_library(offlineproxy SHARED
    main.cpp
    curl_exp.cpp
    console_log.cpp
    console_log.h
    fps_cap.cpp
    fps_cap.h
    Source.def
    #Resource.rc
    resource.h
    pch.h
    "${CMAKE_CURRENT_BINARY_DIR}/generated/serverconfig.h"
)

target_precompile_headers(offlineproxy PRIVATE pch.cpp)
target_link_libraries(offlineproxy PRIVATE
    detours
    CURL::libcurl
    wininet
    winhttp
)
set_target_properties(offlineproxy PROPERTIES
    OUTPUT_NAME ${CURL_NAME}
    OUTPUT_NAME_Debug ${CURL_NAME}
    OUTPUT_NAME_RelWithDebInfo ${CURL_NAME}
)

if (OFFLINEMOD_CONTENT_PROVIDER)
    target_sources(offlineproxy PRIVATE
        content/cp_core.cpp
        content/cp_core.h
        content/cp_post_quest.cpp
        content/cp_post_quest.h
        content/cp_gate_flash.cpp
        content/cp_gate_flash.h
        content/cp_gate_flash_internal.h
        content/cp_gate_flash_logic.cpp
        content/cp_name_fit.cpp
        content/cp_name_fit.h
        content/cp_name_fit_internal.h
        content/cp_name_fit_logic.cpp
        content/cp_hooks.cpp
        content/cp_hooks.h
        content/cp_hooks_internal.h
        content/cp_hooks_logic.cpp
        content/cp_log.cpp
        content/cp_log.h
        content/cp_provider.cpp
        content/cp_provider.h
        content/cp_signatures.h
        content/cp_startup.cpp
        content/cp_startup.h
        content/cp_startup_internal.h
        content/cp_startup_logic.cpp
    )
    target_link_libraries(offlineproxy PRIVATE bcrypt)
endif()

target_compile_definitions(offlineproxy PRIVATE -D_UNICODE -D_WIN32_WINNT=0x601)
target_include_directories(offlineproxy PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
