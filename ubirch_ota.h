/*!
 * @file
 * @brief ubirch_ota.h
 *
 * Firmware Upgrade Procedures.
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
#ifndef UBIRCH_OTA_H
#define UBIRCH_OTA_H

#include "esp_err.h"

esp_err_t ubirch_firmware_upgrade();

#endif //UBIRCH_OTA_H
