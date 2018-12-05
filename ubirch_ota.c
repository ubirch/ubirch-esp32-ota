/*!
 * @file
 * @brief OTA update procedures and verification.
 *
 * Firmware Upgrade Procedures.
 * This is an extension of the example OTA code from Espressif
 * that additionally verifies the Ed25519 signature of the firmware
 * binary.
 *
 * @author Matthias L. Jugel
 * @date   2018-11-28
 *
 * @copyright &copy; 2018 ubirch GmbH (https://ubirch.com)
 *
 * ```
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ```
 */

/* OTA example
   This example code is in the Public Domain (or CC0 licensed, at your option.)
   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <mbedtls/sha512.h>
#include <string.h>
#include <armnacl.h>
#include <ubirch_ed25519.h>
#include <ubirch_protocol.h>
#include <esp_flash_partitions.h>
#include <nvs.h>

#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"

#include "ubirch_ota.h"

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#define BUFFSIZE 1024

#if CONFIG_FIRMWARE_FILE_OVERRIDE == 'y'
#undef UBIRCH_FIRMWARE_FILE
#define UBIRCH_FIRMWARE_FILE CONFIG_FIRMWARE_UPGRADE_FILE
#endif

static const char *TAG = "UBIRCH OTA";

/*an ota data write buffer ready to write to the flash*/
static char ota_write_data[BUFFSIZE + 1] = {0};

extern const uint8_t ubirch_ota_key_pub_start[] asm("_binary_ota_key_pub_start");
extern const uint8_t ubirch_ota_key_pub_end[] asm("_binary_ota_key_pub_end");

extern const uint8_t server_cert_pem_start[] asm("_binary_ota_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ota_ca_cert_pem_end");

// local implementation of the verification function
static inline int
ed25519_verify_ota(const unsigned char *data, size_t len, const unsigned char signature[crypto_sign_BYTES]) {
    return ed25519_verify_key(data, len, signature, ubirch_ota_key_pub_start);
}

static void http_cleanup(esp_http_client_handle_t client) {
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
}

static esp_err_t fetch_firmware_signature(unsigned char *signature, size_t len) {
    esp_err_t err;

    esp_http_client_config_t config = {
            .url = CONFIG_FIRMWARE_UPGRADE_BASE_URL "/" UBIRCH_FIRMWARE_FILE ".sig",
            .cert_pem = (char *) server_cert_pem_start,
    };

    ESP_LOGI(__func__, "fetching: %s", config.url);
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(__func__, "unable to create http client");
        return ESP_FAIL;
    }

    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(__func__, "http connection failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }
    esp_http_client_fetch_headers(client);

    int signature_len = esp_http_client_read(client, (char *) signature, len);
    if (signature_len != 64) {
        ESP_LOGE(__func__, "signature length wrong: %d", signature_len);
        esp_http_client_cleanup(client);
        return ESP_ERR_INVALID_SIZE;
    }

    ESP_LOGI(__func__, "signature received: %d", signature_len);
    ESP_LOG_BUFFER_HEX(__func__, signature, len);

    esp_http_client_cleanup(client);

    return ESP_OK;
}

esp_err_t ubirch_firmware_update() {
    esp_err_t err;

    uint8_t sha_256[32] = {0};
    esp_partition_t partition;

    // get sha256 digest for the partition table
    partition.address = ESP_PARTITION_TABLE_OFFSET;
    partition.size = ESP_PARTITION_TABLE_MAX_LEN;
    partition.type = ESP_PARTITION_TYPE_DATA;
    esp_partition_get_sha256(&partition, sha_256);
    ESP_LOGI(__func__, "partition table hash:");
    ESP_LOG_BUFFER_HEX(__func__, sha_256, 32);

    // get sha256 digest for bootloader
    partition.address = ESP_BOOTLOADER_OFFSET;
    partition.size = ESP_PARTITION_TABLE_OFFSET;
    partition.type = ESP_PARTITION_TYPE_APP;
    ESP_LOGI(__func__, "bootloader hash:");
    ESP_LOG_BUFFER_HEX(__func__, sha_256, 32);

    // get sha256 digest for running partition
    esp_partition_get_sha256(esp_ota_get_running_partition(), sha_256);
    ESP_LOGI(__func__, "current firmware hash:");
    ESP_LOG_BUFFER_HEX(__func__, sha_256, 32);

    // check that the current signature differs, otherwise ignore this update
    unsigned char installed_fw_sig[crypto_sign_BYTES];
    nvs_handle nvs_sig_handle;
    err = nvs_open("__ub_fw", NVS_READONLY, &nvs_sig_handle);
    if (err == ESP_OK) {
        size_t len = 64;
        err = nvs_get_blob(nvs_sig_handle, "sig", installed_fw_sig, &len);
        if (err == ESP_OK) {
            ESP_LOGI(__func__, "installed firmware signature:");
            ESP_LOG_BUFFER_HEXDUMP(__func__, installed_fw_sig, 64, ESP_LOG_INFO);
        } else {
            ESP_LOGE(__func__, "load: %s: %d", esp_err_to_name(err), len);
            ESP_LOGI(__func__, "no old firmware signature or new firmware found, downloading");
        }
    }
    nvs_close(nvs_sig_handle);

    /* update handle : set by esp_ota_begin(), must be freed via esp_ota_end() */
    esp_ota_handle_t update_handle = 0;
    const esp_partition_t *update_partition = NULL;

    const esp_partition_t *configured = esp_ota_get_boot_partition();
    if (!configured) {
        ESP_LOGE(TAG, "OTA is not configured, flash partition invalid");
        return ESP_FAIL;
    }
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!running) {
        ESP_LOGE(TAG, "could not find current running partition");
        return ESP_FAIL;
    }

    if (configured != running) {
        ESP_LOGW(TAG, "Configured OTA boot partition at offset 0x%08x, but running from offset 0x%08x",
                 configured->address, running->address);
        ESP_LOGW(TAG,
                 "(This can happen if either the OTA boot data or preferred boot image become corrupted somehow.)");
    }
    ESP_LOGI(TAG, "Running partition type %d subtype %d (offset 0x%08x)",
             running->type, running->subtype, running->address);

    ESP_LOGI(TAG, "starting OTA process ("UBIRCH_FIRMWARE_FILE")");

    unsigned char signature[64], sha512sum[64];
    err = fetch_firmware_signature(signature, 64);
    if (err != ESP_OK) {
        ESP_LOGE(__func__, "no firmware signature found, aborting");
        return err;
    }

    if(!memcmp(installed_fw_sig, signature, 64)) {
        ESP_LOGW(__func__, "installed firmware signature matches server, aborting");
        return ESP_FAIL;
    }


    mbedtls_sha512_context hash;
    mbedtls_sha512_init(&hash);
    mbedtls_sha512_starts(&hash, 0);

    esp_http_client_config_t config = {
            .url = CONFIG_FIRMWARE_UPGRADE_BASE_URL "/" UBIRCH_FIRMWARE_FILE,
            .cert_pem = (char *) server_cert_pem_start,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialise HTTP connection");
        return ESP_FAIL;
    }
    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }
    esp_http_client_fetch_headers(client);

    update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition) return ESP_ERR_OTA_PARTITION_CONFLICT;
    ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
             update_partition->subtype, update_partition->address);

    err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
        http_cleanup(client);
        return err;
    }
    ESP_LOGI(TAG, "esp_ota_begin succeeded");

    int binary_file_length = 0;
    /*deal with all receive packet*/
    while (1) {
        int data_read = esp_http_client_read(client, ota_write_data, BUFFSIZE);
        if (data_read < 0) {
            ESP_LOGE(TAG, "Error: SSL data read error");
            esp_ota_end(update_handle);
            http_cleanup(client);
            return ESP_FAIL;
        } else if (data_read > 0) {
            mbedtls_sha512_update(&hash, (const unsigned char *) ota_write_data, (size_t) data_read);
            err = esp_ota_write(update_handle, (const void *) ota_write_data, (size_t) data_read);
            if (err != ESP_OK) {
                esp_ota_end(update_handle);
                http_cleanup(client);
                return err;
            }
            binary_file_length += data_read;
        } else if (data_read == 0) {
            ESP_LOGI(TAG, "Connection closed,all data received");
            break;
        }
    }
    ESP_LOGI(TAG, "Total Write binary data length : %d", binary_file_length);
    mbedtls_sha512_finish(&hash, sha512sum);
    ESP_LOG_BUFFER_HEX(TAG, sha512sum, 64);

    const int vrfy_err = ed25519_verify_ota(sha512sum, 64, signature);
    if (vrfy_err != 0) {
        ESP_LOGE(TAG, "firmware signature invalid: %d", vrfy_err);
        esp_ota_end(update_handle);
        http_cleanup(client);
        return ESP_FAIL;
    }

    if (esp_ota_end(update_handle) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed!");
        http_cleanup(client);
        return ESP_FAIL;
    }

    if (esp_partition_check_identity(esp_ota_get_running_partition(), update_partition) == true) {
        ESP_LOGW(TAG, "The current running firmware is same as the firmware just downloaded");
        return ESP_FAIL;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        http_cleanup(client);
        return err;
    }

    err = nvs_open("__ub_fw", NVS_READWRITE, &nvs_sig_handle);
    if (err == ESP_OK) {
        ESP_LOGI(__func__, "committing installed firmware signature");
        err = nvs_set_blob(nvs_sig_handle, "sig", signature, 64);
        if (err == ESP_OK) {
            err = nvs_commit(nvs_sig_handle);
            if (err != ESP_OK) ESP_LOGE(__func__, "can't commit firmware signature");
        }
        nvs_close(nvs_sig_handle);
    }
    ESP_LOGI(TAG, "Prepare to restart system!");
    esp_restart();
}
