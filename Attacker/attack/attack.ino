// TTGO T-Beam — Security Test Device
// Click button = navigate menu
// Hold button (1 second) = execute
// Supports: CRC Test 1, CRC Test 2, Unauthorized Access, Replay Attack

#include <SPI.h>
#include <RadioLib.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <AESLib.h>
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET   -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
#define LORA_SS   18
#define LORA_RST  14
#define LORA_DIO0 26
#define LORA_DIO1 33
SX1276 radio = new Module(LORA_SS, LORA_DIO0, LORA_RST, LORA_DIO1);
#define BUTTON_PIN    38
#define HOLD_TIME     1000 

const byte aesKey[16] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
};
AESLib aesLib;

const int TOTAL_MENUS = 4;
const char* menuNames[] = {
  "1.CRC Test 1",      
  "2.CRC Test 2",      
  "3.Unauth Access",   
  "4.Replay Attack"    
};
int currentMenu = 0;
int packetCounter = 0;  
byte computeCRC(const String &data) {
  byte crc = 0;
  for (size_t i = 0; i < data.length(); i++) crc ^= data[i];
  return crc;
}

void showMenu() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("== SELECT TEST ==");
  display.println("Click: Navigate");
  display.println("Hold : Execute");
  display.println("> " + String(menuNames[currentMenu]));
  display.setCursor(0, 56);
  display.println(String(currentMenu + 1) + "/" + String(TOTAL_MENUS));
  display.display();
}

void showRunning(String testName) {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("== RUNNING ==");
  display.println(testName);
  display.println("Sending...");
  display.display();
}

void showResult(String line1, String line2 = "", String line3 = "",String line4 = "", String line5 = "") {
  display.clearDisplay();
  display.setCursor(0, 0);
  if (line1 != "") { display.setCursor(0, 0);  display.println(line1); }
  if (line2 != "") { display.setCursor(0, 11); display.println(line2); }
  if (line3 != "") { display.setCursor(0, 22); display.println(line3); }
  if (line4 != "") { display.setCursor(0, 33); display.println(line4); }
  if (line5 != "") { display.setCursor(0, 44); display.println(line5); }
  display.display();
  delay(3000);
  showMenu();
}

int readButton() {
  if (digitalRead(BUTTON_PIN) == HIGH) return 0; 

  unsigned long pressStart = millis();
  while (digitalRead(BUTTON_PIN) == LOW) {
    delay(10);
    if (millis() - pressStart > HOLD_TIME) {
      while (digitalRead(BUTTON_PIN) == LOW) delay(10);
      return 2; 
    }
  }
  delay(50); 
  return 1;  
}

int buildEncryptedPacket(byte* encrypted, String nodeID, int pktNum, bool corruptByte5, bool corruptCRC) {
  String gpsData    = "Lat=4.596053;Lon=101.111429";
  unsigned long ts  = millis();

  String basePayload = gpsData + " NODEID=" + nodeID + " PKT="    + String(pktNum) + " TS="     + String(ts);

  byte crcVal = computeCRC(basePayload);

  String payloadWithCRC;
  if (corruptCRC) {
    payloadWithCRC = basePayload + " CRC=" + String(crcVal ^ 0xFF, HEX);
  } else {
    payloadWithCRC = basePayload + " CRC=" + String(crcVal, HEX);
  }
  byte buffer[256];
  int payloadLen = payloadWithCRC.length();
  buffer[0] = (payloadLen >> 8) & 0xFF;
  buffer[1] = payloadLen & 0xFF;
  memcpy(buffer + 2, payloadWithCRC.c_str(), payloadLen);

  int totalLen  = payloadLen + 2;
  int paddedLen = totalLen;
  if (paddedLen % 16 != 0) paddedLen += 16 - (paddedLen % 16);
  for (int i = totalLen; i < paddedLen; i++) buffer[i] = 0;
  byte ivCopy[16] = {0};
  int encLen = aesLib.encrypt(buffer, paddedLen, encrypted, aesKey, 128, ivCopy);

  if (corruptByte5) {
    encrypted[5] ^= 0xFF;
  }

  return encLen;
}

// TEST 1 — CRC Test 1 (corrupt byte 5, causes Bad Length / No CRC field)
void runCRCTest1() {
  showRunning("CRC Test 1");
  packetCounter++;

  byte encrypted[256];
  int encLen = buildEncryptedPacket(encrypted, "001", packetCounter, false, false);

  encrypted[encLen - 5] ^= 0xFF;

  Serial.println("=============================");
  Serial.println("[CRC TEST 1] Corrupt byte encLen-5");
  Serial.println("[CRC TEST 1] PKT#" + String(packetCounter));

  int state = radio.transmit(encrypted, encLen);

  if (state == RADIOLIB_ERR_NONE) {
    Serial.println("[CRC TEST 1] Sent — receiver should show No CRC Field");
    showResult("== CRC TEST 1 ==", "Corrupt: end byte", "Sent OK", "Receiver should", "show: No CRC Field");
  } else {
    Serial.println("[CRC TEST 1] Failed: " + String(state));
    showResult("CRC TEST 1 FAIL", "Code: " + String(state));
  }
}


// TEST 2 — CRC Test 2 (corrupt CRC value before encrypt, clean decrypt but mismatch)
void runCRCTest2() {
  showRunning("CRC Test 2");
  packetCounter++;

  byte encrypted[256];
  int encLen = buildEncryptedPacket(encrypted, "001", packetCounter, false, true);

  Serial.println("=============================");
  Serial.println("[CRC TEST 2] Corrupted CRC value in payload");
  Serial.println("[CRC TEST 2] PKT#" + String(packetCounter));

  int state = radio.transmit(encrypted, encLen);

  if (state == RADIOLIB_ERR_NONE) {
    Serial.println("[CRC TEST 2] Sent — receiver should show CRC MISMATCH");
    showResult("== CRC TEST 2 ==", "Corrupt: CRC val", "Sent OK", "Receiver should", "show: CRC MISMATCH");
  } else {
    Serial.println("[CRC TEST 2] Failed: " + String(state));
    showResult("CRC TEST 2 FAIL", "Code: " + String(state));
  }
}


// TEST 3 — Unauthorized Access (plaintext, node 999)
void runUnauthTest() {
  showRunning("Unauth Access");

  String fakePayload = "Lat=1.111111;Lon=2.222222 NODEID=999 PKT=1 TS=0 CRC=ff";

  Serial.println("=============================");
  Serial.println("[UNAUTH] Sending plaintext, NodeID=999");
  Serial.println("[UNAUTH] Payload: " + fakePayload);
  int state = radio.transmit(fakePayload);

  if (state == RADIOLIB_ERR_NONE) {
    Serial.println("[UNAUTH] Sent — receiver should show UNAUTHORIZED");
    showResult("== UNAUTH TEST ==", "Node : 999", "No encryption", "Receiver should", "show: UNAUTHORIZED");
  } else {
    Serial.println("[UNAUTH] Failed: " + String(state));
    showResult("UNAUTH FAIL", "Code: " + String(state));
  }
}

// TEST 4 — Replay Attack (node 001, always sends PKT=1)
void runReplayTest() {
  showRunning("Replay Attack");

  int replayPKT = 1;

  byte encrypted[256];
  int encLen = buildEncryptedPacket(encrypted, "001", replayPKT, false, false);

  Serial.println("=============================");
  Serial.println("[REPLAY] NodeID=001, forcing PKT=1");
  Serial.println("[REPLAY] First send will succeed, subsequent sends rejected");

  int state = radio.transmit(encrypted, encLen);

  if (state == RADIOLIB_ERR_NONE) {
    Serial.println("[REPLAY] Sent PKT=1 — if already received, receiver rejects");
    showResult("== REPLAY TEST ==", "Node : 001", "PKT# : 1 (forced)", "Receiver should", "show: REPLAY!");
  } else {
    Serial.println("[REPLAY] Failed: " + String(state));
    showResult("REPLAY FAIL", "Code: " + String(state));
  }
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
  display.println("== TEST DEVICE ==");
  display.println("Initializing...");
  display.display();

  SPI.begin(5, 19, 27, LORA_SS);
  int state = radio.begin(433.0, 125.0, 7, 5, 0x12, 17, 8);

  if (state != RADIOLIB_ERR_NONE) {
    Serial.println("LoRa Failed: " + String(state));
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("LoRa FAILED!");
    display.println("Code: " + String(state));
    display.display();
    while (true);
  }

  Serial.println("=============================");
  Serial.println("  SECURITY TEST DEVICE READY");
  Serial.println("  Click = Navigate");
  Serial.println("  Hold  = Execute");
  Serial.println("=============================");

  showMenu();
}

void loop() {
  int btn = readButton();

  if (btn == 1) {
    currentMenu = (currentMenu + 1) % TOTAL_MENUS;
    showMenu();

  } else if (btn == 2) {
    Serial.println("Executing: " + String(menuNames[currentMenu]));
    switch (currentMenu) {
      case 0: runCRCTest1();   break;
      case 1: runCRCTest2();   break;
      case 2: runUnauthTest(); break;
      case 3: runReplayTest(); break;
    }
  }
}