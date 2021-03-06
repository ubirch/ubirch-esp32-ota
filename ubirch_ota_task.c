/*!
 * @file
 * @brief firmware update task
 *
 * ...
 *
 * @author Matthias L. Jugel
 * @date   2018-12-01
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

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <ubirch_ota.h>
#include <esp_netif.h>
#include <esp_log.h>
#include "ubirch_ota_task.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-noreturn"

void ubirch_ota_task(void *pvParameters) {
    TickType_t interval;
    interval = pvParameters ? *((TickType_t *) pvParameters) : FIRMWARE_UPDATE_CHECK_INTERVAL;
    ESP_LOGI(__func__, "checking firmware every %ds", interval / 1000);

    for (;;) {
        vTaskDelay(interval);
        tcpip_adapter_ip_info_t ip;
        if ((tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_ETH, &ip) == ESP_OK && ip.ip.addr != 0) ||
            (tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip) == ESP_OK && ip.ip.addr != 0)) {
            ESP_LOGD(__func__, "network up: " IPSTR, IP2STR(&ip.ip));
            // the network is up, polling firmware update
            ubirch_firmware_update();
        } else {
            ESP_LOGE(__func__, "network not available, skipping firmware update");
        }
    }
}

#pragma GCC diagnostic pop