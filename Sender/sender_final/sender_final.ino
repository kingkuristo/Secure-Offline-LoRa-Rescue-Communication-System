// TTGO T-Beam Sender
// Secure LoRa Emergency Communication System
#include <SPI.h>
#include <RadioLib.h>
#include <TinyGPSPlus.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <AESLib.h>

TinyGPSPlus gps;
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET   -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
#define LORA_SS   18
#define LORA_RST  14
#define LORA_DIO0 26
#define LORA_DIO1 33
SX1276 radio = new Module(LORA_SS, LORA_DIO0, LORA_RST, LORA_DIO1);
HardwareSerial GPSSerial(1);

#define BUTTON_PIN 38
#define NODEID "001"

const byte aesKey[16] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
};
AESLib aesLib;

int packetCounter = 0;
byte computeCRC(const String &data) { //crc calculation
  byte crc = 0;
  for (size_t i = 0; i < data.length(); i++) crc ^= data[i];
  return crc;
}

void setup() {
  Serial.begin(115200);
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("OLED failed");
    while (true);
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("=== SENDER ===");
  display.println("LoRa: Initializing");
  display.display();

  GPSSerial.begin(9600, SERIAL_8N1, 34, 12);

  SPI.begin(5, 19, 27, LORA_SS);
  int state = radio.begin(433.0, 125.0, 7, 5, 0x12, 17, 8); //lora config

  if (state != RADIOLIB_ERR_NONE) {
    Serial.println("LoRa Init Failed: " + String(state));
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("LoRa FAILED!");
    display.println("Code: " + String(state));
    display.display();
    while (true);
  }

  Serial.println("=============================");
  Serial.println("  SENDER READY");
  Serial.println("  NodeID : " + String(NODEID));
  Serial.println("  Freq   : 433MHz");
  Serial.println("  SF/BW  : 7/125k");
  Serial.println("=============================");

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("=== SENDER ===");
  display.println("LoRa  : OK");
  display.println("Freq  : 433MHz");
  display.println("Node  : " + String(NODEID));
  display.println("");
  display.println("Press btn for SOS");
  display.display();
}

void loop() {  // for emergency trigger process
  if (digitalRead(BUTTON_PIN) == LOW) {
    getAndSendGPS();
    delay(2000); 
  }
  while (GPSSerial.available() > 0) gps.encode(GPSSerial.read());
}

void getAndSendGPS() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("=== SOS PRESSED ===");
  display.println("Getting GPS...");
  display.display();

  unsigned long gpsStart = millis();
  while (!gps.location.isValid() && (millis() - gpsStart) < 30000) { // usually 60s for real situation
    while (GPSSerial.available() > 0) gps.encode(GPSSerial.read());
  }

  String gpsData;
  if (gps.location.isValid()) {
    gpsData = "Lat=" + String(gps.location.lat(), 6) +
              ";Lon=" + String(gps.location.lng(), 6);
    Serial.println("[GPS] Fix obtained: " + gpsData);
  } else {
    gpsData = "Lat=3.204774;Lon=101.704401";  //fallback @ demo purpose if indoor
    Serial.println("[GPS] No fix — using fallback: " + gpsData);
  }

  packetCounter++; //packet counter
  String basePayload = gpsData + " NODEID=" + String(NODEID) + " PKT="    + String(packetCounter); //payload construction

  unsigned long sendTS = millis(); //for timestamp logging

  String fullPayload = basePayload + " TS=" + String(sendTS);
  byte crc = computeCRC(fullPayload);
  String payloadWithCRC = fullPayload + " CRC=" + String(crc, HEX);

  byte buffer[256];
  int payloadLen = payloadWithCRC.length();
  buffer[0] = (payloadLen >> 8) & 0xFF;
  buffer[1] = payloadLen & 0xFF;
  memcpy(buffer + 2, payloadWithCRC.c_str(), payloadLen);

  int totalLen  = payloadLen + 2;
  int paddedLen = totalLen;
  if (paddedLen % 16 != 0) paddedLen += 16 - (paddedLen % 16);
  for (int i = totalLen; i < paddedLen; i++) buffer[i] = 0;

  byte encrypted[256];
  byte ivCopy[16] = {0}; 
  int encLen = aesLib.encrypt(buffer, paddedLen, encrypted, aesKey, 128, ivCopy); //encryption 

  Serial.println("=============================");
  Serial.println("[SEND] PKT#   : " + String(packetCounter));
  Serial.println("[SEND] NodeID : " + String(NODEID));
  Serial.println("[SEND] GPS    : " + gpsData);
  Serial.println("[SEND] TS     : " + String(sendTS) + "ms");
  Serial.println("[SEND] Payload: " + payloadWithCRC);

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("=== SENDING ===");
  display.println("PKT# : " + String(packetCounter));
  display.println("Node : " + String(NODEID));
  display.println(gpsData.substring(0, 21)); // fit on screen
  display.println("TS   : " + String(sendTS));
  display.display();

  int state = radio.transmit(encrypted, encLen);

  if (state == RADIOLIB_ERR_NONE) {
    Serial.println("[SEND] Status : OK");
    Serial.println("=============================");

    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("=== SENT OK ===");
    display.println("PKT# : " + String(packetCounter));
    display.println("Node : " + String(NODEID));
    display.println("TS   : " + String(sendTS) + "ms");
    display.println("=====================");
    display.println("Press again for SOS");
    display.display();

  } else {
    Serial.println("[SEND] Status : FAILED code=" + String(state));
    Serial.println("=============================");

    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("=== SEND FAIL ===");
    display.println("Code: " + String(state));
    display.display();
  }
}