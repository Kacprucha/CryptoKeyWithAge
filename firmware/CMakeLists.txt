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

file(GLOB CALIB_SOURCES
    libs/cryptoauthlib/lib/atca_basic.c
    libs/cryptoauthlib/lib/atca_device.c
    libs/cryptoauthlib/lib/atca_iface.c
    libs/cryptoauthlib/lib/atca_helpers.c
    libs/cryptoauthlib/lib/atca_cfgs.c
    libs/cryptoauthlib/lib/atca_debug.c
    libs/cryptoauthlib/lib/atca_command.c
    libs/cryptoauthlib/lib/atca_execution.c 
    libs/cryptoauthlib/lib/hal/atca_hal.c
    libs/cryptoauthlib/lib/host/atca_host.c 
    libs/cryptoauthlib/lib/calib/calib_basic.c
    libs/cryptoauthlib/lib/calib/calib_command.c
    libs/cryptoauthlib/lib/calib/calib_execution.c
    libs/cryptoauthlib/lib/calib/calib_info.c
    libs/cryptoauthlib/lib/calib/calib_random.c
    libs/cryptoauthlib/lib/calib/calib_genkey.c
    libs/cryptoauthlib/lib/calib/calib_gendig.c
    libs/cryptoauthlib/lib/calib/calib_updateextra.c
    libs/cryptoauthlib/lib/calib/calib_ecdh.c
    libs/cryptoauthlib/lib/calib/calib_read.c
    libs/cryptoauthlib/lib/calib/calib_write.c
    libs/cryptoauthlib/lib/calib/calib_execute.c
    libs/cryptoauthlib/lib/calib/calib_lock.c
    libs/cryptoauthlib/lib/calib/calib_nonce.c
    libs/cryptoauthlib/lib/calib/calib_sign.c
    libs/cryptoauthlib/lib/calib/calib_verify.c
    libs/cryptoauthlib/lib/calib/calib_checkmac.c
    libs/cryptoauthlib/lib/calib/calib_derive_key.c
    libs/cryptoauthlib/lib/calib/calib_packet.c
    libs/cryptoauthlib/lib/calib/calib_helpers.c
    libs/cryptoauthlib/lib/crypto/atca_crypto_sw_sha2.c
    libs/cryptoauthlib/lib/crypto/hashes/sha2_routines.c
)

add_library(cryptoauth STATIC ${CALIB_SOURCES})

target_include_directories(cryptoauth PUBLIC
    libs/cryptoauthlib/lib
    src/crypto   
)

add_executable(${PROJECT} 
    src/main.c 
    src/atecc608a_config.c
    src/usb/usb_descriptors.c 
    src/usb/usb_handler.c 
    src/usb/config_handler.c
    src/usb/crypto_handler.c
    src/crypto/protocol.c 
    src/crypto/hal_i2c_pico.c
)

target_include_directories(${PROJECT} PRIVATE src)
target_link_libraries(${PROJECT} pico_stdlib hardware_i2c tinyusb_device tinyusb_board cryptoauth)

if (PICO_CYW43_SUPPORTED)
    target_link_libraries(${PROJECT} pico_cyw43_arch_none)
endif()

pico_add_extra_outputs(${PROJECT})