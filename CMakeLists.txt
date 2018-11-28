set(COMPONENT_SRCS ubirch_ota.c)
set(COMPONENT_ADD_INCLUDEDIRS ".")

# ubirch ota key for verification of the firmware download
if (CMAKE_BUILD_TYPE MATCHES RELEASE OR CMAKE_BUILD_TYPE MATCHES MINSIZEREL)
    set(UB_OTA_KEY "${CMAKE_CURRENT_LIST_DIR}/../../certificates/ota_key_prod.pub")
else ()
    set(UB_OTA_KEY "${CMAKE_CURRENT_LIST_DIR}/../../certificates/ota_key.pub")
endif ()
if (NOT EXISTS "${UB_OTA_KEY}")
    message(WARNING "Missing ubirch OTA public key: ${UB_OTA_KEY}")
endif ()
set(UB_OTA_KEY_MASTER "${CMAKE_CURRENT_LIST_DIR}/../../certificates/ota_key_prod.pub")
if (NOT EXISTS "${UB_OTA_KEY_MASTER}")
    message(WARNING "Missing ubirch OTA master public key: ${UB_OTA_KEY_MASTER}")
endif ()

# ca_cert.pem should be located in the main <project directory/certificates> dir.
set(CA_CERT_FILE "${CMAKE_CURRENT_LIST_DIR}/../../certificates/ota_ca_cert.pem")
if (NOT EXISTS "${CA_CERT_FILE}")
    message(WARNING "Missing firmware update server certificate file: ${CA_CERT_FILE}")
endif ()
set(COMPONENT_EMBED_TXTFILES "${CA_CERT_FILE} ${UB_OTA_KEY} ${UB_OTA_KEY_MASTER}")

set(COMPONENT_REQUIRES esp32 esp_http_client spi_flash nvs_flash bootloader_support app_update ubirch-mbed-nacl-cm0)
register_component()