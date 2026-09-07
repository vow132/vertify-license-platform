cmake_minimum_required(VERSION 3.16)
project(vertify-sdk C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    # 商业级发布加固：CFG/ASLR/DEP/栈保护/调试信息剥离
    add_compile_options(/W4 /permissive- /sdl /guard:cf)
    add_link_options(/GUARD:CF /DYNAMICBASE /NXCOMPAT /OPT:REF /OPT:ICF)
else()
    add_compile_options(-Wall -Wextra)
endif()

add_library(vertify_sdk STATIC
    src/sdk.cpp
    src/util.cpp
    src/cng.cpp
    src/http.cpp
    src/device.cpp
    src/store.cpp
    src/x25519.cpp
    third_party/ed25519/src/verify.c
    third_party/ed25519/src/sha512.c
    third_party/ed25519/src/fe.c
    third_party/ed25519/src/ge.c
    third_party/ed25519/src/sc.c
)

target_include_directories(vertify_sdk PUBLIC include)
target_include_directories(vertify_sdk PRIVATE src third_party/ed25519/src)
target_link_libraries(vertify_sdk PUBLIC bcrypt ncrypt winhttp crypt32 shlwapi advapi32)

# C 库链接顺序（MinGW）
if (MINGW)
    target_link_options(vertify_sdk PUBLIC -static)
endif()

add_executable(activate_demo examples/activate_demo/main.cpp)
target_link_libraries(activate_demo PRIVATE vertify_sdk)

add_executable(selftest tests/selftest.cpp)
target_link_libraries(selftest PRIVATE vertify_sdk)
