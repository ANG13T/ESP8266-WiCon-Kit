#include "SH1106Wire.h"
#include "./esppl_functions.h"
#include <ESP8266WiFi.h>
SH1106Wire display(0x3C, SDA, SCL); // use builtin i2C

// button and led pins use (https://iotbytes.wordpress.com/nodemcu-pinout/) for reference
const int leftButton = 2;
const int rightButton = 0;
const int led = 13;

// display state (0 = home, 1 = packet monitoring, 2 = deauth checker, 3 = access point creation)
int displayState = 0;

// button states and previous states
int lState = 0; int plState = 1;
int rState = 0; int prState = 1;

String packet[7];
String devices[100][3]; int devCnt = 0;
String srcMac, ssid, src, dest;
char srcOctet[2], destOctet[2];
int addr, fst, ft;
String pktType;

int filter = 0; // 0 = ALL, 1 = DEAUTH, 2 = PROBE REQ

void cb(esppl_frame_info *info) { /*--- WiFi Scanner Function ---*/
  ssid = "";
  src = "";  // source

  Serial.print("\n");
  Serial.print("FT: ");
  Serial.print((int) info->frametype);

  Serial.print(" FST: ");
  Serial.print((int) info->framesubtype);

  Serial.print(" SRC: ");
  for (int i = 0; i < 6; i++) Serial.printf("%02x", info->sourceaddr[i]);
  for (int i = 0; i < 6; i++) {
    sprintf(srcOctet, "%02x", info->sourceaddr[i]);
    src += srcOctet;
  }

  Serial.print(" DEST: ");
  for (int i = 0; i < 6; i++) Serial.printf("%02x", info->receiveraddr[i]);
  dest = "";   // dest MAC
  for (int i = 0; i < 6; i++) {
    sprintf(destOctet, "%02x", info->receiveraddr[i]); dest += destOctet;
  }

  Serial.print(" RSSI: ");
  Serial.print(info->rssi);

  Serial.print(" SEQ: ");
  Serial.print(info->seq_num);

  Serial.print(" CHNL: ");
  Serial.print(info->channel);

  if (info->ssid_length > 0) {
    Serial.print(" SSID: ");
    for (int i = 0; i < info->ssid_length; i++) Serial.print((char) info->ssid[i]);
  }
  if (info->ssid_length > 0) {
    for (int i = 0; i < info->ssid_length; i++) {
      ssid += (char) info->ssid[i];
    }
  }

  // append packets metadata to packet list
  packet[0] = (String) info->frametype;
  packet[1] = (String) info->framesubtype;
  packet[2] = src;
  packet[3] = dest;
  packet[4] = (String) info->rssi;
  packet[5] = (String) info->channel;
  packet[6] = ssid;
  ft = packet[0].toInt(); fst = packet[1].toInt();
}

void printPacket() { // function to print wifi packets to the screen

  // flag packet w/ frame + subframe type
  if (filter == 0 || (filter == 1 && ft == 0 and fst == 12) || (filter == 2 && ft == 0 and fst == 4 )) {
    if      (ft == 0 and (fst == 0 or fst == 1)) pktType = "Association Req.";
    else if (ft == 0 and (fst == 2 or fst == 3)) pktType = "Re-Assoc";
    else if (ft == 0 and fst == 4) pktType = "Probe Request";
    else if (ft == 0 and fst == 8 ) pktType = "Beacon";
    else if (ft == 0 and fst == 10) pktType = "Disassociation";
    else if (ft == 0 and fst == 11) pktType = "Authentication";
    else if (ft == 0 and fst == 12) pktType = "De-Authentication";
    else if (ft == 0) pktType = "Management";
    else if (ft == 1) pktType = "Control";
    else if (ft == 2) pktType = "Data";
    else pktType = "Extension";

    srcMac = packet[2];
    display.drawString(0, 14, "PKT: "); display.drawString(30, 14, pktType);
    display.drawString(0, 22, "SRC: "); display.drawString(30, 22, srcMac);
    display.drawString(0, 30, "DST: "); display.drawString(30, 30, packet[3]);
    display.drawString(0, 38, "RSS: "); display.drawString(30, 38, packet[4]);
    display.drawString(0, 46, "CH: "); display.drawString(30, 46, packet[5]);
    display.drawString(0, 54, "SSID: ");
    if (packet[6].length() < 18) {
      display.drawString(30, 54, packet[6]);
    }
    else if (packet[6].length() > 1) {
      display.drawString(30, 54, packet[6].substring(0, 17 ) + "...");
    }

  }
}

// check if button is pressed
void checkForPress() {
  lState = digitalRead(leftButton);
  rState = digitalRead(rightButton);

  if (lState == 0 && lState != plState && filter > 0) {
    filter--;
  }
  else if (rState == 0 && rState != prState && filter < 2) {
    filter++;
  }
  else if (lState == 0 && lState != plState) {
    filter = 2;
  }
  else if (rState == 0 && rState != prState) {
    filter = 0;
  }

  plState = lState;
  prState = rState;
}


void printHomeScreen() {
  display.drawString(12, 12, "WiCon Kit");
  display.drawString(12, 30, "By Angelina Tsuboi");
}

void updateMenu() { // update scroll menu and packet type selection

  if (displayState == 1) {
    display.drawLine(0, 12, 127, 12);
    display.drawLine(20, 0, 20, 12);
    display.fillTriangle(8, 5, 11, 2, 11, 8);
    display.drawLine(107, 0, 107, 12);
    display.fillTriangle(119, 5, 116, 2, 116, 8);

    if (filter == 0) {
      display.drawString(55, 0, "ALL");
    }
    else if (filter == 1) {
      display.drawString(42, 0, "DEAUTH");
    }
    else {
      display.drawString(45, 0, "PROBE");
    }
  }

}

void setup() {
  pinMode(leftButton, INPUT_PULLUP);
  pinMode(rightButton, INPUT_PULLUP);
  pinMode(led, OUTPUT);

  delay(500);
  // digitalWrite(led, HIGH);
  Serial.begin(115200);
  display.init();
  display.flipScreenVertically();
  display.setTextAlignment(TEXT_ALIGN_LEFT);
  display.setFont(ArialMT_Plain_10);
  display.drawString(42, 54, "DEAUTH");
  esppl_init(cb);
}

void loop() {
  if(displayState == 0) {
      display.clear();
     printHomeScreen();
     display.display();
     delay(0);
    
  }else if (displayState == 1) {
    esppl_sniffing_start();


    while (displayState == 1) {
      for (int i = 1; i < 15; i++ ) {
        esppl_set_channel(i);
        while (esppl_process_frames()) {
          //
        }
      }

      digitalWrite(led, HIGH);
      checkForPress();
      display.clear();
      updateMenu();
      printPacket();
      display.display();
      //if (filter>0) delay(600); //dumb delay to display packets longer
      delay(0);
    }
  }
}
