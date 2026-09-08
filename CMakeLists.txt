cmake_minimum_required(VERSION 3.15)
project(IronVeil CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/bin/Release")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/bin/Release")

enable_language(ASM_MASM)

add_library(IronVeilStub SHARED
    stub/StubEntry.asm
    stub/SyscallStub.asm
    stub/StubMain.cpp
    src/Encryptor.cpp
)
target_compile_options(IronVeilStub PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W3 /O2 /GS- /Gy>)
target_link_options(IronVeilStub PRIVATE /NODEFAULTLIB /ENTRY:StubEntryPoint /MERGE:.rdata=.text)

add_executable(IronVeil
    src/main.cpp
    src/PeParser.cpp
    src/PeBuilder.cpp
    src/Encryptor.cpp
)
target_compile_options(IronVeil PRIVATE /W3 /O2)
target_link_libraries(IronVeil PRIVATE kernel32 advapi32)
add_dependencies(IronVeil IronVeilStub)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test/TestTarget.cpp")
    add_executable(TestTarget
        test/TestTarget.cpp
    )
    target_compile_options(TestTarget PRIVATE /W3 /O2)
    target_link_libraries(TestTarget PRIVATE kernel32 user32)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test/test_peb.cpp")
    add_executable(test_peb
        test/test_peb.cpp
        stub/SyscallStub.asm
    )
    target_compile_options(test_peb PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W3 /O2>)
    target_link_libraries(test_peb PRIVATE kernel32 user32)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test/minidbg.cpp")
    add_executable(minidbg
        test/minidbg.cpp
    )
    target_compile_options(minidbg PRIVATE /W3 /O2)
    target_link_libraries(minidbg PRIVATE kernel32)
endif()
