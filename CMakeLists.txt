set(COMPONENT_SRCS ubirch_ota.c)
set(COMPONENT_ADD_INCLUDEDIRS ".")

# the certificates directory is expected in the project root directory
set(PROJECT_CERT_DIR "${CMAKE_CURRENT_LIST_DIR}/../../certificates")

# ubirch ota key for verification of the firmware download
if (CMAKE_BUILD_TYPE MATCHES RELEASE OR CMAKE_BUILD_TYPE MATCHES MINSIZEREL)
    set(UB_OTA_KEY "${PROJECT_CERT_DIR}/ota_key_prod.pub")
else ()
    set(UB_OTA_KEY "${PROJECT_CERT_DIR}/ota_key.pub")
endif ()
if (NOT EXISTS "${UB_OTA_KEY}")
    message(WARNING "Missing ubirch OTA public key: ${UB_OTA_KEY}")
endif ()

# ca_cert.pem should be located in the main <project directory/certificates> dir.
set(CA_CERT_FILE "${PROJECT_CERT_DIR}/ota_ca_cert.pem")
if (NOT EXISTS "${CA_CERT_FILE}")
    message(WARNING "Missing firmware update server certificate file: ${CA_CERT_FILE}")
endif ()
set(COMPONENT_EMBED_TXTFILES "${CA_CERT_FILE} ${UB_OTA_KEY}")

set(COMPONENT_REQUIRES ubirch-protocol)
set(COMPONENT_PRIV_REQUIRES bootloader_support app_update esp_http_client mbedtls)
register_component()