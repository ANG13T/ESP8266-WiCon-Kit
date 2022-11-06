<img src="https://github.com/angelina-tsuboi/ESP8266-WiCon-Kit/blob/master/Assets/WiCon_Icon_Large.png" alt="WiCon logo" width="500"/>

### A compact and portable WiFi reconnaissance suite based on the ESP8266

## Features
- Packet Monitor with 11 filter types
- Deauthentication and Disassociation Detector (HAXX)
- FTP Honeypot with Canary Tokens
- Web Server (WIP)
- CSV Data logging (WIP)

## Components
| Component | Purpose |
| --- | --- |
| ESP8266 | Monitor WiFi data & initialize honeypot
| 128x64 OLED | Give a visual display of WiFi data |
| 2x Push Buttons | Gather user input |
| LED | Indicate HAXX attacks |

## Hardware Setup
**128x64 OLED** 
| OLED Pin | ESP8266 GPIO | Node MCU Pin |
| --- | --- | --- |
| SCK | GPIO5 | D1 |
| SDA | GPIO4 | D2 |

**Left Push Button** 
| ESP8266 GPIO | Node MCU Pin |
| --- | --- |
| GPIO2 | D4 |

**Right Push Button** 
| ESP8266 GPIO | Node MCU Pin |
| --- | --- |
| GPIO0 | D3 |

**LED** 
| ESP8266 GPIO | Node MCU Pin |
| --- | --- |
| GPIO13 | D7 |

## Schematic
<img src="https://github.com/angelina-tsuboi/ESP8266-WiCon-Kit/blob/master/Assets/WiCon_Schematic.png" alt="WiCon logo" width="700"/>

## Image
<img src="https://github.com/angelina-tsuboi/ESP8266-WiCon-Kit/blob/master/Assets/WiCon_Preview.png" alt="WiCon preview" width="700"/>

## Set up
- Arduino IDE with the following URL added under Preferences -> Additional board manager URL's: http://arduino.esp8266.com/stable/package_esp8266com_index.json

- ESP8266 boards added in Arduino IDE by going to Tools -> Boards -> Boards Manager, and installing ESP8266 by ESP8266 Community

- ESPcanary library installed in Arduino IDE by going to Sketch -> Include Library -> Manage Libraries and installing "ESPcanary" by Dan Hoover

- Install Zip file from https://github.com/wonho-maker/Adafruit_SH1106 and unzip the file inside Arduino -> libraries

- Adafruit GFX library installed in Arduino IDE by going to Sketch -> Include Library -> Manage Libraries and installing "Adafruit GFX Library" by Adafruit

## Special Thanks and Resources
The WiCon kit is a derivation of previous ESP8266 WiFi recon features developed by Spacehuhn, Alex Lynd, and Kody Kinzie. Check out the resources below!
- [SpacehuhnTech/DeauthDetector](https://github.com/SpacehuhnTech/DeauthDetector)
- [HakCat-Tech/HaxxDetector](https://github.com/HakCat-Tech/HaxxDetector)
- [skickar/ESP8266_Router_Honeypot](https://github.com/skickar/ESP8266_Router_Honeypot)
