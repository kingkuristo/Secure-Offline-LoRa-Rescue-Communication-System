# Secure Offline LoRa Rescue Communication System

A secure, encrypted emergency communication system designed for search and rescue operations where cellular networks are unavailable. This project was developed as a Final Year Project (FYP).

## Features & Security Testing
The system is designed to support the following security and performance tests:
* **Transmission Delay (5.3.2):** High-accuracy timestamping captured immediately before transmission.
* **Reliability (5.3.3):** Packet delivery tracking.
* **Confidentiality (5.4.1):** Full AES-128 encryption of payloads.
* **Integrity (5.4.2):** CRC-8 checksum verification for every packet.
* **Unauthorized Access Detection (5.4.3):** Rejection of rogue nodes and unencrypted plaintext.
* **Replay Attack Protection (5.4.4):** Sequential packet numbering to block duplicated transmissions.

## Hardware Requirements
* **Sender:** TTGO T-Beam (ESP32 + SX1276 + GPS)
* **Receiver:** Heltec WiFi LoRa 32 V3 (ESP32 + SX1262 + OLED)
* **Attacker:** TTGO T-Beam (ESP32 + SX1276 + GPS)

## Dependencies
Ensure the following libraries are installed in your Arduino IDE:
* `RadioLib`
* `AESLib`
* `TinyGPSPlus`
* `Adafruit_SSD1306` & `Adafruit_GFX`

## 🔧 Configuration
The AES key must match on both devices:
```cpp
const byte aesKey[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
