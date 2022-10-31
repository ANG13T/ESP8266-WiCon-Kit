/*
     ___       __   ___  ________  ________  ________           ___  __    ___  _________
    |\  \     |\  \|\  \|\   ____\|\   __  \|\   ___  \        |\  \|\  \ |\  \|\___   ___\
     \ \  \    \ \  \ \  \ \  \___|\ \  \|\  \ \  \\ \  \       \ \  \/  /|\ \  \|___ \  \_|
      \ \  \  __\ \  \ \  \ \  \    \ \  \\\  \ \  \\ \  \       \ \   ___  \ \  \   \ \  \
       \ \  \|\__\_\  \ \  \ \  \____\ \  \\\  \ \  \\ \  \       \ \  \\ \  \ \  \   \ \  \
        \ \____________\ \__\ \_______\ \_______\ \__\\ \__\       \ \__\\ \__\ \__\   \ \__\
         \|____________|\|__|\|_______|\|_______|\|__| \|__|        \|__| \|__|\|__|    \|__|


   A compact and portable WiFi reconnaissance suite based on the ESP8266
   https://github.com/angelina-tsuboi/ESP8266-WiCon-Kit

   By Angelina Tsuboi (angelinatsuboi.net)

*/

#if LWIP_FEATURES && !LWIP_IPV6

#define HAVE_NETDUMP 0

#ifndef STASSID
#define STASSID "NETWORK_NAME" // set the SSID (name) of the Wi-Fi network the ESP8266 will connect to for internet
#define STAPSK  "NETWORK_PASS" // set the password of the Wi-Fi network the ESP8266 will connect to for internet
#define NEWSSID  "Wicon_Wifi" // set the name (SSID) of the Wi-Fi network the ESP8266 will create
#define NEWPASS  "123456" // set the password of the Wi-Fi network the ESP8266 will create
#endif

#include "SH1106Wire.h"
#include "./esppl_functions.h"
#include "graphics.h"
#include <ESP8266WiFi.h>
#include <lwip/napt.h>
#include <lwip/dns.h>
#include <dhcpserver.h>
#include <ESPCanary.h>

#define NAPT 1000
#define NAPT_PORT 10

#if HAVE_NETDUMP

#include <NetDump.h>

void dump(int netif_idx, const char* data, size_t len, int out, int success) {
  (void)success;
  Serial.print(out ? F("out ") : F(" in "));
  Serial.printf("%d ", netif_idx);

  // optional filter example: if (netDump_is_ARP(data))
  {
    netDump(Serial, data, len);
    //netDumpHex(Serial, data, len);
  }
}
#endif

String canary = "http://canarytokens.com/feedback/articles/tags/f7jx4e7s0i91k9uzgonweoapy/contact.php";  //grab FREE web bug/URL tokens at http://canarytokens.org
String ftp_user = "admin";    //if you replace this with "%" it will accept ANY username
String ftp_pass = "password"; //if you replace this with "%" it will accept ANY password
bool append_ip = false;       //if you are using a canary token, leave this as false
String append_char = "?";     //if you are using a canary token, this doesn't matter
//if you are using your own webhook,with a bunch of GET
//parameters then you would want this to be "&" so the IP
//address becomes the final GET parameter

FtpServer ftpSrv;   //set #define FTP_DEBUG in ESPCanary.h to see ftp verbose on serial

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
    if (pkt_type == 0xC0) {
      isDeauthentication = false;
    } else {
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

int filter = 0;

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


const char *filterNames[12] = {
  "ALL",
  "De-Authentication",
  "Probe Request",
  "Association Req.",
  "Re-Assoc",
  "Beacon",
  "De-Authentication",
  "Authentication",
  "Management",
  "Control",
  "Data",
  "Extension"
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
           || (filter == 3 && ft == 0 and (fst == 0 or fst == 1))
           || (filter == 4 && ft == 0 and (fst == 2 or fst == 3))
           || (filter == 5 && ft == 0 and fst == 8)
           || (filter == 6 && ft == 0 and fst == 10)
           || (filter == 7 && ft == 0 and fst == 11)
           || (filter == 8 && ft == 0)
           || (filter == 9 && ft == 1)
           || (filter == 10 && ft == 2)
           || filter == 11
         );
}

void printPacket() { // function to print wifi packets to the screen

  // flag packet w/ frame + subframe type
  if      (ft == 0 and (fst == 0 or fst == 1)) pktType = "Association Req.";
  else if (ft == 0 and (fst == 2 or fst == 3)) pktType = "Re-Assoc";
  else if (ft == 0 and fst == 4) pktType = "Probe Request";
  else if (ft == 0 and fst == 8) pktType = "Beacon";
  else if (ft == 0 and fst == 10) pktType = "Disassociation";
  else if (ft == 0 and fst == 11) pktType = "Authentication";
  else if (ft == 0 and fst == 12) pktType = "De-Authentication";
  else if (ft == 0) pktType = "Management";
  else if (ft == 1) pktType = "Control";
  else if (ft == 2) pktType = "Data";
  else pktType = "Extension";

  if (filter == 0 || (String)filterNames[filter] == pktType) {
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
    Serial.print(displayState);
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

void checkForBackButton() {
  lState = digitalRead(leftButton);
  if (lState == 0) {
    displayState = 0;
  }
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
  Serial.begin(115200);
  pinMode(leftButton, INPUT_PULLUP);
  pinMode(rightButton, INPUT_PULLUP);
  pinMode(led, OUTPUT);


  Serial.println();
  Serial.println("     ___       __   ___  ________  ________  ________           ___  __    ___  _________");
  Serial.println("    |\\  \\     |\\  \\|\\  \\|\\   ____\\|\\   __  \\|\\   ___  \\        |\\  \\|\\  \\ |\\  \\|\\___   ___\\");
  Serial.println("     \\ \\  \\    \\ \\  \\ \\  \\ \\  \\___|\\ \\  \\|\\  \\ \\  \\\\ \\  \\       \\ \\  \\/  /|\\ \\  \\|___ \\  \\_|");
  Serial.println("      \\ \\  \\  __\\ \\  \\ \\  \\ \\  \\    \\ \\  \\\\\\  \\ \\  \\\\ \\  \\       \\ \\   ___  \\ \\  \\   \\ \\  \\\\");
  Serial.println("       \\ \\  \\|\\__\\_\\  \\ \\  \\ \\  \\____\\ \\  \\\\\\  \\ \\  \\\\ \\  \\       \\ \\  \\\\ \\  \\ \\  \\   \\ \\  \\\\");
  Serial.println("        \\ \\____________\\ \\__\\ \\_______\\ \\_______\\ \\__\\\\ \\__\\       \\ \\__\\\\ \\__\\ \\__\\   \\ \\__\\\\");
  Serial.println("         \\|____________|\\|__|\\|_______|\\|_______|\\|__| \\|__|        \\|__| \\|__|\\|__|    \\|__|");
  Serial.println();
  Serial.println("\ngithub.com/angelina-tsuboi/ESP8266-WiCon-Kit");
  Serial.println("A compact and portable WiFi reconnaissance suite based on the ESP8266");
  Serial.println();

  display.init();
  display.flipScreenVertically();
  display.setTextAlignment(TEXT_ALIGN_LEFT);
  display.setFont(ArialMT_Plain_10);
  display.drawXbm(5, 5, icon_width, icon_height, icon);
  display.drawString(17, 45, "By Angelina Tsuboi");
  display.display();

#if HAVE_NETDUMP
  phy_capture = dump;
#endif

  delay(500);

  WiFi.mode(WIFI_STA);
  WiFi.begin(STASSID, STAPSK);
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print('.');
    delay(500);
  }
  Serial.printf("\nSTA: %s (dns: %s / %s)\n",
                WiFi.localIP().toString().c_str(),
                WiFi.dnsIP(0).toString().c_str(),
                WiFi.dnsIP(1).toString().c_str());

  // give DNS servers to AP side
  dhcps_set_dns(0, WiFi.dnsIP(0));
  dhcps_set_dns(1, WiFi.dnsIP(1));

  WiFi.softAPConfig(  // enable AP, with android-compatible google domain
    IPAddress(172, 217, 28, 254),
    IPAddress(172, 217, 28, 254),
    IPAddress(255, 255, 255, 0));
  WiFi.softAP(NEWSSID, NEWPASS);
  Serial.printf("AP: %s\n", WiFi.softAPIP().toString().c_str());

  Serial.printf("Heap before: %d\n", ESP.getFreeHeap());
  err_t ret = ip_napt_init(NAPT, NAPT_PORT);
  Serial.printf("ip_napt_init(%d,%d): ret=%d (OK=%d)\n", NAPT, NAPT_PORT, (int)ret, (int)ERR_OK);
  if (ret == ERR_OK) {
    ret = ip_napt_enable_no(SOFTAP_IF, 1);
    Serial.printf("ip_napt_enable_no(SOFTAP_IF): ret=%d (OK=%d)\n", (int)ret, (int)ERR_OK);
    if (ret == ERR_OK) {
      Serial.printf("WiFi Network '%s' with password '%s' is now NATed behind '%s'\n", NEWSSID, NEWPASS, STASSID);
    }
  }
  Serial.printf("Heap after napt init: %d\n", ESP.getFreeHeap());
  if (ret != ERR_OK) {
    Serial.printf("NAPT initialization failed\n");
  }

  /////FTP Setup, ensure SPIFFS is started before ftp;  /////////
  if (SPIFFS.begin()) {
    Serial.println("SPIFFS opened!");
    ftpSrv.begin(ftp_user, ftp_pass, canary, append_ip, append_char); //username, password for ftp.  set ports in ESPCanary.h  (default 21, 50009 for PASV)
    esppl_init(cb);
  }
}

// HAXX Detector

void startAttack() {
  digitalWrite(led, HIGH);
  attackInProgress = true;
}

void displayHaxxScreen() {
  display.clear();
  String displayText = "Deauthentication Attack!";
  if (attackInProgress && isDeauthentication) {
    displayText = "Deauthentication Attack!";
    display.drawXbm(50, 5, warning_width, warning_height, warning);
    display.drawString(5, 44, displayText);
  } else if (attackInProgress && !isDeauthentication) {
    displayText = "Dissassociation Attack!";
    display.drawXbm(50, 5, warning_width, warning_height, warning);
    display.drawString(5, 44, displayText);
  } else {
    display.drawXbm(50, 5, wifi_width, wifi_height, wifi);
    display.drawString(20, 44, displayText);
  }

  display.display();
}

void checkHaxxPress() {
  lState = digitalRead(leftButton);
  if (lState == 0) {
    displayState = 0;
  }
}

void endAttack() {
  digitalWrite(led, LOW);
  attackInProgress = false;
}

// FTP Honey Pot Display
void displayFTPHoneyPot() {
  display.clear();
  display.drawLine(0, 12, 127, 12);
  display.drawLine(20, 0, 20, 12);
  display.fillTriangle(8, 5, 11, 2, 11, 8);
  display.drawString(25, 0, "FTP Honeypot");
  display.drawString(0, 14, "STASSID: "); display.drawString(48, 14, STASSID);
  display.drawString(0, 27, "SSID: "); display.drawString(30, 27, NEWSSID);
  display.drawString(0, 40, "PASS: "); display.drawString(32, 40, NEWPASS);
  display.display();
}

#else

#error "NAPT not supported in this configuration"

void setup() {
  Serial.begin(115200);
  Serial.printf("\n\nNAPT not supported in this configuration\n");
}

#endif

void loop() {
  ftpSrv.handleFTP();
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
    checkHaxxPress();
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
  } else if (displayState == 3) {
    displayFTPHoneyPot();
    checkForBackButton();
  }
}
