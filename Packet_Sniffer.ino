#include "SH1106Wire.h"
#include "./esppl_functions.h"
#include <ESP8266WiFi.h>
SH1106Wire display(0x3C, SDA, SCL); // use builtin i2C

// button and led pins use (https://iotbytes.wordpress.com/nodemcu-pinout/) for reference
const int leftButton = 2;
const int rightButton = 0;
const int led = 13;

// display state (0 = home, 1 = packet monitoring, 2 = haxx detector, 3 = ftp honeypot)
int displayState = 0;

const char *options[3] = {
  "Packet Monitor",
  "Haxx Detector",
  "FTP Honeypot"
};

// Haxx Detector Variables
const short channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}; // Max: US 11, EU 13, JAP 14
int ch_index { 0 };
int packet_rate { 0 };
int attack_counter { 0 };
unsigned long update_time { 0 };
unsigned long ch_time { 0 };
bool attackInProgress = false;
bool isDeauthentication = false;

void haxx_sniffer(uint8_t *buf, uint16_t len) {
  if (!buf || len < 28) return;
  byte pkt_type = buf[12];

  if (pkt_type == 0xA0 || pkt_type == 0xC0) { // flag deauth & dissassociation frames
    ++packet_rate;
    if(pkt_type == 0xC0) {
      isDeauthentication = false;
    }else{
      isDeauthentication = true;
    }
  }
}

int menuPointer = 0;

// button states and previous states
int lState = 0;
int rState = 0; int prState = 1;

String packet[7];
String devices[100][3]; int devCnt = 0;
String srcMac, ssid, src, dest;
char srcOctet[2], destOctet[2];
int addr, fst, ft;
String pktType;

int filter = 0; // 0 = ALL, 1 = DEAUTH, 2 = PROBE REQ

const char *filters[12] = {
  "ALL",
  "DEAUTH",
  "PROBE",
  "ASSOC",
  "R-ASSOC",
  "BEACON",
  "D-ASSOC",
  "AUTH",
  "MANGMNT",
  "CTRL",
  "DATA",
  "EXTEN"
};

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

void displayMenu() {
  for (int i = 0; i < 3; i++) {
    if (menuPointer == i) {
      char buf[2048];
      const char *pretext = "> ";
      const char *text = options[i];
      strcpy(buf, pretext);
      strcat(buf, text);
      display.drawString(10, 10 + (12 * i), buf);
    } else {
      display.drawString(10, 10 + (12 * i), options[i]);
    }
  }
  display.drawLine(0, 48, 127, 48);
}

bool checkPacketReturnTypes(int filter, int ft, int fst) {
  return (
    filter == 0  
    || (filter == 1 && ft == 0 and fst == 12)
    || (filter == 2 && ft == 0 and fst == 4 )
  );
}

void printPacket() { // function to print wifi packets to the screen

  // flag packet w/ frame + subframe type
  if (checkPacketReturnTypes(filter, ft, fst)) {
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

void menuButtonPress() {
  lState = digitalRead(leftButton);
  rState = digitalRead(rightButton);

  // uni-directional menu scroller (left = navigation, right = selection)
  if (lState == LOW && menuPointer == 2) {
    menuPointer = 0;
    delay(300);
  } else if (lState == LOW) {
    menuPointer += 1;
    delay(300);
  }

  if (rState == LOW) {
    displayState = menuPointer + 1;
    delay(300);
  }
}

// check if button is pressed
void checkForPress() {
  lState = digitalRead(leftButton);
  rState = digitalRead(rightButton);

  if (rState == 0 && rState != prState && filter < 11) {
    filter++;
  }
  else if (rState == 0 && rState != prState) {
    filter = 0;
  }

  if (lState == 0) {
    displayState = 0;
  }

  prState = rState;
}


void printHomeScreen() {
  display.drawString(40, 0, "WiCon Kit");
  displayMenu();
  display.drawString(18, 50, "By Angelina Tsuboi");
}

void updateMenu() { // update scroll menu and packet type selection

  if (displayState == 1) {
    display.drawLine(0, 12, 127, 12);
    display.drawLine(20, 0, 20, 12);
    display.fillTriangle(8, 5, 11, 2, 11, 8);
    display.drawLine(107, 0, 107, 12);
    display.drawString(116, 0, "+");

    if (filter == 0) {
      display.drawString(55, 0, (String)filters[filter]);
    }
    else if (filter == 1) {
      display.drawString(42, 0, (String)filters[filter]);
    }
    else {
      display.drawString(45, 0, (String)filters[filter]);
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
  esppl_init(cb);
}

// HAXX Detector

void startAttack() {
  digitalWrite(led, HIGH);
  attackInProgress = true;
}

void displayHaxxScreen() {
  display.clear();
    String displayText = "Scanning Packets...";
    if(attackInProgress && isDeauthentication) {
      displayText = "Deauthentication Attack!";
    }else if(attackInProgress && !isDeauthentication) {
      displayText = "Dissassociaten Attack!";
    }
    display.drawString(10, 40, displayText);
    display.display();
}

void endAttack(){
  digitalWrite(led, LOW);
  attackInProgress = false;
}


void loop() {
  if (displayState == 0) {
    menuButtonPress();
    display.clear();
    printHomeScreen();
    display.display();
    delay(0);

  } else if (displayState == 1) {
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
      // if (filter>0) delay(600); (delay to make packets appear longer)
      delay(0);
    }
  } else if (displayState == 2) {
    unsigned long current_time = millis();
    displayHaxxScreen();
    if (current_time - update_time >= (sizeof(channels) * 100)) {
      update_time = current_time;

      if (packet_rate >= 1) {
        ++attack_counter;
      }
      else {
        if (attack_counter >= 1) endAttack();
        attack_counter = 0;
      }

      if (attack_counter == 1) {
        startAttack();
      }
      packet_rate = 0;
    }

    // Channel hopping
    if (sizeof(channels) > 1 && current_time - ch_time >= 100) {
      ch_time = current_time; // Update time variable
      ch_index = (ch_index + 1) % (sizeof(channels) / sizeof(channels[0]));
      short ch = channels[ch_index];
      esppl_set_channel(ch);
    }
  }
}
