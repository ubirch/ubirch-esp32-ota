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
#include "freertos/FreeRTOS.h"

#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"

#include "ubirch_ota.h"

#define BUFFSIZE 1024

static const char *TAG = "UBIRCH OTA";

/*an ota data write buffer ready to write to the flash*/
static char ota_write_data[BUFFSIZE + 1] = {0};

extern const uint8_t ubirch_ota_key_pub_start[] asm("_binary_ota_key_pub_start");
extern const uint8_t ubirch_ota_key_pub_end[] asm("_binary_ota_key_pub_end");

extern const uint8_t server_cert_pem_start[] asm("_binary_ota_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ota_ca_cert_pem_end");

static int ed25519_verify(const unsigned char *data, size_t len, const unsigned char signature[crypto_sign_BYTES],
                              const unsigned char public_key[crypto_sign_PUBLICKEYBYTES]) {
    crypto_uint16 smlen = (crypto_uint16) (crypto_sign_BYTES + len);
    crypto_uint16 mlen;

    unsigned char *sm = (unsigned char *) malloc(smlen);
    if (!sm) return -1;

    unsigned char *m = (unsigned char *) malloc(smlen);
    if (!m) {
        free(sm);
        return -1;
    }

    // initialize signed message structure
    memcpy(sm, signature, crypto_sign_BYTES);
    memcpy(sm + crypto_sign_BYTES, data, len);

    // verify signature
    int ret = crypto_sign_open(m, &mlen, sm, smlen, public_key);

    free(m);
    free(sm);

    return ret;
}

static void http_cleanup(esp_http_client_handle_t client) {
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
}

static esp_err_t fetch_firmware_signature(unsigned char *signature, size_t len) {
    esp_err_t err;

    esp_http_client_config_t config = {
            .url = CONFIG_FIRMWARE_UPGRADE_BASE_URL "/" CONFIG_FIRMWARE_UPGRADE_FILE ".sig",
            .cert_pem = (char *) server_cert_pem_start,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "unable to open connection");
        return ESP_FAIL;
    }
    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "http open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }
    esp_http_client_fetch_headers(client);

    int data_read = esp_http_client_read(client, (char *) signature, len);
    if (data_read < 0) {
        ESP_LOGE(TAG, "SSL data read error");
        http_cleanup(client);
        return ESP_FAIL;
    } else if (data_read == 64) {
        ESP_LOGI(TAG, "signature received");
        ESP_LOG_BUFFER_HEX(TAG, signature, len);
        return ESP_OK;
    }

    return ESP_FAIL;
}

esp_err_t ubirch_firmware_upgrade() {
    esp_err_t err;
    /* update handle : set by esp_ota_begin(), must be freed via esp_ota_end() */
    esp_ota_handle_t update_handle = 0;
    const esp_partition_t *update_partition = NULL;

    ESP_LOGI(TAG, "Starting OTA example...");

    const esp_partition_t *configured = esp_ota_get_boot_partition();
    const esp_partition_t *running = esp_ota_get_running_partition();

    if (configured != running) {
        ESP_LOGW(TAG, "Configured OTA boot partition at offset 0x%08x, but running from offset 0x%08x",
                 configured->address, running->address);
        ESP_LOGW(TAG,
                 "(This can happen if either the OTA boot data or preferred boot image become corrupted somehow.)");
    }
    ESP_LOGI(TAG, "Running partition type %d subtype %d (offset 0x%08x)",
             running->type, running->subtype, running->address);

    unsigned char signature[64], sha512sum[64];
    fetch_firmware_signature(signature, 64);

    mbedtls_sha512_context hash;
    mbedtls_sha512_init(&hash);
    mbedtls_sha512_starts(&hash, 0);

    esp_http_client_config_t config = {
            .url = CONFIG_FIRMWARE_UPGRADE_BASE_URL "/" CONFIG_FIRMWARE_UPGRADE_FILE,
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
    ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
             update_partition->subtype, update_partition->address);
    assert(update_partition != NULL);

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
            http_cleanup(client);
            return ESP_FAIL;
        } else if (data_read > 0) {
            mbedtls_sha512_update(&hash, (const unsigned char *) ota_write_data, (size_t) data_read);
            err = esp_ota_write(update_handle, (const void *) ota_write_data, (size_t) data_read);
            if (err != ESP_OK) {
                http_cleanup(client);
                return err;
            }
            binary_file_length += data_read;
            ESP_LOGD(TAG, "Written image length %d", binary_file_length);
        } else if (data_read == 0) {
            ESP_LOGI(TAG, "Connection closed,all data received");
            break;
        }
    }
    ESP_LOGI(TAG, "Total Write binary data length : %d", binary_file_length);
    mbedtls_sha512_finish(&hash, sha512sum);
    ESP_LOG_BUFFER_HEX(TAG, sha512sum, 64);

    const int vrfy_err = ed25519_verify(sha512sum, 64, signature, ubirch_ota_key_pub_start);
    if(vrfy_err != 0) {
        ESP_LOGE(TAG, "firmware signature invalid: %d", vrfy_err);
        http_cleanup(client);
        return ESP_FAIL;
    }

    if (esp_ota_end(update_handle) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed!");
        http_cleanup(client);
        return ESP_FAIL;
    }
    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        http_cleanup(client);
        return err;
    }
    ESP_LOGI(TAG, "Prepare to restart system!");
    esp_restart();
}
