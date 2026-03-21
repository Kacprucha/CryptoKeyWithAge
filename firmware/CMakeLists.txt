# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0-a4)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(PICO_BOARD pico_w CACHE STRING "Board type")

set(PROJECT crypto_key_firmware)

include(pico_sdk_import.cmake)

project(${PROJECT} C CXX ASM)
pico_sdk_init()

add_executable(${PROJECT} 
    src/main.c 
    src/usb/usb_descriptors.c 
    src/usb/usb_handler.c 
    src/crypto/protocol.c 
)

target_include_directories(${PROJECT} PRIVATE src)
target_link_libraries(${PROJECT} pico_stdlib hardware_i2c tinyusb_device tinyusb_board)
pico_add_extra_outputs(${PROJECT})