<img src="https://github.com/angelina-tsuboi/ESP8266-WiCon-Kit/blob/master/Assets/WiCon_Icon_Large.png" alt="WiCon logo" width="500" height="150"/>

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

## Schematics

## Special Thanks and Resources
