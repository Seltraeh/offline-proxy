# Unit tests for the content provider (OfflineMod.win32/content).  Win32 only:
# the hook ABI tests use MSVC x86 inline assembly, like the hooks themselves.
add_executable(content_provider_tests
    test_main.cpp
    test_util.h
    fake_broker.h
    ../OfflineMod.win32/content/cp_core.cpp
    ../OfflineMod.win32/content/cp_gate_flash_logic.cpp
    ../OfflineMod.win32/content/cp_name_fit_logic.cpp
    ../OfflineMod.win32/content/cp_log.cpp
    ../OfflineMod.win32/content/cp_provider.cpp
    ../OfflineMod.win32/content/cp_hooks_logic.cpp
    ../OfflineMod.win32/content/cp_startup_logic.cpp
    # The startup attach itself (Session 17): TestStartupAttachOrder runs it, with the real
    # Detours, on the client EXE laid out in this process.
    ../OfflineMod.win32/content/cp_startup.cpp
)
target_include_directories(content_provider_tests PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../OfflineMod.win32/content"
    "${CMAKE_BINARY_DIR}/OfflineMod.win32/generated"
)
target_compile_definitions(content_provider_tests PRIVATE
    -D_WIN32_WINNT=0x601
    "BF_TEST_FIXTURES=\"${CMAKE_CURRENT_LIST_DIR}/fixtures\""
)
target_link_libraries(content_provider_tests PRIVATE detours bcrypt wininet)
# Keep build/bin for the deployable libcurl.dll only.
set_target_properties(content_provider_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/tests"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/tests"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/tests")

# The client binaries are read from disk (never modified) to prove the
# signature table matches the supported build; set BF_APPX_DIR to the
# extracted Appx folder.  Without it those cases are reported as skipped.
add_test(NAME content_provider_tests COMMAND content_provider_tests)
