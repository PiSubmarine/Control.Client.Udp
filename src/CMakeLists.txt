include("${_build_cmake_local}")

message("Adding library: ${PISUBMARINE_MODULE_NAME}")
add_library(${PISUBMARINE_MODULE_NAME}
        PiSubmarine/Control/Client/Udp/Client.cpp
        "../public/PiSubmarine/Control/Client/Udp/Client.h")
target_include_directories(${PISUBMARINE_MODULE_NAME} PUBLIC "../public")
PiSubmarineInitTarget(${PISUBMARINE_MODULE_NAME})

PiSubmarineAddDependency("https://github.com/PiSubmarine/Control.Api.git" "")
target_link_libraries(${PISUBMARINE_MODULE_NAME} PUBLIC PiSubmarine.Control.Api)

PiSubmarineAddDependency("https://github.com/PiSubmarine/Control.Serialization.Api.git" "")
target_link_libraries(${PISUBMARINE_MODULE_NAME} PUBLIC PiSubmarine.Control.Serialization.Api)

PiSubmarineAddDependency("https://github.com/PiSubmarine/Lease.Api.git" "")
target_link_libraries(${PISUBMARINE_MODULE_NAME} PUBLIC PiSubmarine.Lease.Api)

PiSubmarineAddDependency("https://github.com/PiSubmarine/Security.Aead.Api.git" "")
target_link_libraries(${PISUBMARINE_MODULE_NAME} PUBLIC PiSubmarine.Security.Aead.Api)

PiSubmarineAddDependency("https://github.com/PiSubmarine/Security.Nonce.Api.git" "")
target_link_libraries(${PISUBMARINE_MODULE_NAME} PUBLIC PiSubmarine.Security.Nonce.Api)

PiSubmarineAddDependency("https://github.com/PiSubmarine/Udp.Api.git" "")
target_link_libraries(${PISUBMARINE_MODULE_NAME} PUBLIC PiSubmarine.Udp.Api)
