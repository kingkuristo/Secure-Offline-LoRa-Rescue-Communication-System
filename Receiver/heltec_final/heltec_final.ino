// Heltec WiFi LoRa 32 V3 Receiver
// Secure LoRa Emergency Communication System
#include <RadioLib.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <AESLib.h>

#define SCREEN_WIDTH  128
#define SCREEN_HEIGHT  64
#define OLED_SDA       17
#define OLED_SCL       18
#define OLED_RST       21
#define Vext           36
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RST);

SX1262 radio = new Module(8, 14, 12, 13);

const byte aesKey[16] = {  //the key
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
};
AESLib aesLib;

int totalReceived     = 0;
int totalRejected     = 0;
int lastPacketNum     = -1;
int replayCount       = 0;
int unauthorizedCount = 0;

const String authorizedNodes[] = {"001"};  //registerd node
const int numAuthorized = 1;

volatile bool receivedFlag = false;
void IRAM_ATTR setFlag() { receivedFlag = true; }

byte computeCRC(const String &data) {
  byte crc = 0;
  for (size_t i = 0; i < data.length(); i++) crc ^= data[i];
  return crc;
}

String parseField(const String &payload, const String &key) {
  int start = payload.indexOf(key);
  if (start == -1) return "";
  start += key.length();
  int end = payload.indexOf(';', start);
  if (end == -1) end = payload.indexOf(' ', start);
  if (end == -1) end = payload.length();
  return payload.substring(start, end);
}

bool isAuthorizedNode(const String &nodeID) {
  for (int i = 0; i < numAuthorized; i++) {
    if (authorizedNodes[i] == nodeID) return true;
  }
  return false;
}

bool isPlaintext(byte *data, int len) {  //plaintext detection
  for (int i = 0; i < len; i++) {
    if (data[i] < 0x20 || data[i] > 0x7E) return false;
  }
  return true;
}

void showOLED(String l1, String l2="", String l3="",
              String l4="", String l5="", String l6="") {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  if (l1 != "") { display.setCursor(0, 0);  display.println(l1); }
  if (l2 != "") { display.setCursor(0, 11); display.println(l2); }
  if (l3 != "") { display.setCursor(0, 22); display.println(l3); }
  if (l4 != "") { display.setCursor(0, 33); display.println(l4); }
  if (l5 != "") { display.setCursor(0, 44); display.println(l5); }
  if (l6 != "") { display.setCursor(0, 55); display.println(l6); }
  display.display();
}

void showError(String msg) {
  showOLED("!!! ERROR !!!", msg,
           "Rx:" + String(totalReceived),
           "Rj:" + String(totalRejected));
  Serial.println("ERROR: " + msg);
}

void setup() {
  Serial.begin(115200);
  delay(500);

  pinMode(Vext, OUTPUT);
  digitalWrite(Vext, LOW);
  delay(100);

  pinMode(OLED_RST, OUTPUT);
  digitalWrite(OLED_RST, HIGH);
  delay(100);
  digitalWrite(OLED_RST, LOW);
  delay(100);
  digitalWrite(OLED_RST, HIGH);
  delay(100);

  Wire.begin(OLED_SDA, OLED_SCL);

  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("OLED init failed");
    while (true);
  }
  showOLED("Booting...");
  Serial.println("OLED OK");

  showOLED("Booting...", "Init LoRa...");

  int state = radio.begin(433.0, 125.0, 7, 5, 0x12, 14, 8); //lora config
  if (state != RADIOLIB_ERR_NONE) {
    Serial.println("LoRa init failed, code: " + String(state));
    showOLED("LoRa FAILED!", "Code: " + String(state),
             "", "Check:", "- Antenna", "- Board select");
    while (true);
  }

  radio.setDio1Action(setFlag);
  radio.startReceive();

  Serial.println("LoRa OK");
  Serial.println("=============================");
  Serial.println("  RECEIVER READY - ALL TESTS");
  Serial.println("=============================");

  showOLED("=== RECEIVER ===",
           "LoRa  : OK",
           "Freq  : 433MHz",
           "SF/BW : 7/125k",
           "Tests : ACTIVE",
           "Waiting SOS...");
}

void loop() {
  if (!receivedFlag) return;
  receivedFlag = false;

  unsigned long arrivalTime = millis();

  int packetLen = radio.getPacketLength();
  byte encrypted[256] = {0};
  int state = radio.readData(encrypted, packetLen);  //securing packet

  if (state != RADIOLIB_ERR_NONE) {
    totalRejected++;
    showError("Read: " + String(state));
    radio.startReceive();
    return;
  }

  float rssi = radio.getRSSI();   //for testing purpose
  float snr  = radio.getSNR();    //for testing purpose

  Serial.println("\n=============================");
  Serial.println("PKT ARRIVED | T=" + String(arrivalTime) +
                 "ms RSSI=" + String(rssi) + " SNR=" + String(snr));

  Serial.print("[ENCRYPTED] ");
  for (int i = 0; i < packetLen; i++) {
    if (encrypted[i] < 0x10) Serial.print("0");
    Serial.print(encrypted[i], HEX);
    Serial.print(" ");
  }
  Serial.println();

  if (isPlaintext(encrypted, packetLen)) {
    char plainBuf[256] = {0};
    memcpy(plainBuf, encrypted, packetLen);
    String plainStr  = String(plainBuf);
    String rogueNode = parseField(plainStr, "NODEID=");

    unauthorizedCount++;
    totalRejected++;

    Serial.println("[SECURITY] PLAINTEXT DETECTED - NO ENCRYPTION!");
    Serial.println("[SECURITY] Rogue payload : " + plainStr);
    Serial.println("[SECURITY] Rogue NodeID  : " + rogueNode);
    Serial.println("[SECURITY] UNAUTHORIZED  - PKT REJECTED");
    Serial.println("[SECURITY] Total unauth  : " + String(unauthorizedCount));
    Serial.println("[SECURITY] Total rejected: " + String(totalRejected));
    Serial.println("=============================");

    showOLED("!! UNAUTHORIZED !!", "Node: " + rogueNode, "No encryption", "PKT REJECTED", "Unauth: " + String(unauthorizedCount), "Rj: "    + String(totalRejected));
    radio.startReceive();
    return;
  }

  byte decrypted[256] = {0};
  byte ivCopy[16] = {0};
  int decLen = aesLib.decrypt(encrypted, packetLen, decrypted, aesKey, 128, ivCopy);  //decryption method

  if (decLen < 2) {
    totalRejected++;
    showError("Decrypt FAIL");
    radio.startReceive();
    return;
  }

  int payloadLen = ((int)decrypted[0] << 8) | decrypted[1];
  if (payloadLen <= 0 || payloadLen > decLen - 2) {
    totalRejected++;
    showError("Bad length");
    radio.startReceive();
    return;
  }

  char payloadBuf[256] = {0};
  memcpy(payloadBuf, decrypted + 2, payloadLen);
  String payload = String(payloadBuf);
  Serial.println("[DECRYPTED] " + payload);

  int crcIdx = payload.lastIndexOf(" CRC=");
  if (crcIdx == -1) {
    totalRejected++;
    showError("No CRC field");
    radio.startReceive();
    return;
  }

  String dataWithoutCRC = payload.substring(0, crcIdx);
  String receivedCRCStr = payload.substring(crcIdx + 5);
  receivedCRCStr.trim();

  byte expectedCRC = computeCRC(dataWithoutCRC);
  byte receivedCRC = (byte) strtol(receivedCRCStr.c_str(), nullptr, 16);

  if (expectedCRC != receivedCRC) { //crc verify
    totalRejected++;
    Serial.println("[CRC] MISMATCH! Got:" + receivedCRCStr +
                   " Expected:" + String(expectedCRC, HEX));
    showOLED("!! CRC FAIL !!", "Got:      " + receivedCRCStr, "Expected: " + String(expectedCRC, HEX), "PKT REJECTED", "Rx:" + String(totalReceived),
             "Rj:" + String(totalRejected));
    radio.startReceive();
    return;
  }
  Serial.println("[CRC] OK");

  String lat    = parseField(dataWithoutCRC, "Lat=");
  String lon    = parseField(dataWithoutCRC, "Lon=");
  String nodeID = parseField(dataWithoutCRC, "NODEID=");
  String pktStr = parseField(dataWithoutCRC, "PKT=");
  String tsStr  = parseField(dataWithoutCRC, "TS=");

  int           pktNum   = pktStr.toInt();
  unsigned long senderTS = (unsigned long) tsStr.toInt();

  unsigned long delay_ms = (arrivalTime > senderTS) ? (arrivalTime - senderTS) : 0;  //for testing purpose

  if (!isAuthorizedNode(nodeID)) {  //unauthorized rejection
    unauthorizedCount++;
    totalRejected++;
    Serial.println("[SECURITY] UNAUTHORIZED NODE: " + nodeID);
    Serial.println("[SECURITY] Total unauth: " + String(unauthorizedCount));
    showOLED("!! UNAUTH NODE !!", "Node: " + nodeID, "Encrypted but", "not registered", "Unauth: " + String(unauthorizedCount), "Rj: "    + String(totalRejected));
    radio.startReceive();
    return;
  }

  if (pktNum <= lastPacketNum) { //replay detection
    replayCount++;
    totalRejected++;
    Serial.println("[SECURITY] REPLAY DETECTED! PKT=" + String(pktNum) +
                   " LastValid=" + String(lastPacketNum));
    Serial.println("[SECURITY] Total replays: " + String(replayCount));
    showOLED("!! REPLAY !!", "PKT#" + String(pktNum) + " rejected", "Last valid: #" + String(lastPacketNum), "Replays: "     + String(replayCount), "Rx:" + String(totalReceived), "Rj:" + String(totalRejected));
    radio.startReceive();
    return;
  }
  lastPacketNum = pktNum;
  totalReceived++;

  Serial.println("=============================");
  Serial.println("[VALID PKT]");
  Serial.println("NodeID  : " + nodeID + " [AUTHORIZED]");
  Serial.println("PKT#    : " + String(pktNum));
  Serial.println("Lat     : " + lat);
  Serial.println("Lon     : " + lon);
  Serial.println("Delay   : " + String(delay_ms) + " ms");
  Serial.println("RSSI    : " + String(rssi)      + " dBm");
  Serial.println("SNR     : " + String(snr)       + " dB");
  Serial.println("Rx OK   : " + String(totalReceived));
  Serial.println("Rejected: " + String(totalRejected));
  Serial.println("Replays : " + String(replayCount));
  Serial.println("Unauth  : " + String(unauthorizedCount));
  Serial.println("Maps    : https://maps.google.com/?q=" + lat + "," + lon);
  Serial.println("=============================");

  showOLED(
    "SOS #" + String(pktNum) + " [" + nodeID + "]",
    "Lat : " + lat,
    "Lon : " + lon,
    "Dly : " + String(delay_ms) + "ms",
    "RSSI: " + String(rssi, 0)  + "dBm",
    "Rx:"  + String(totalReceived) + " Rj:" + String(totalRejected)
  );

  radio.startReceive();
}