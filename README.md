![ubirch logo](https://ubirch.de/wp-content/uploads/2018/10/cropped-uBirch_Logo.png)

# ESP32 OTA component

This is a component for using OTA on the ESP32 and IDF.
This component requires a certificates directory in the project home that contains some
certificates for the update server SSL connection as well as public keys for the verification
of downloaded firmware.

## Usage

- run `make menuconfig` to update the base url and the firmware file name for the OTA update
- set up the `ota_ca_cert.pem` and the `ota_key.pub` file to use for verification
- sign the firmware using the `bin/fw_sign.py` script
- upload the signed firmware to your update server
- run the initial firmware and call `ubirch_firmware_update()` to update the firmware