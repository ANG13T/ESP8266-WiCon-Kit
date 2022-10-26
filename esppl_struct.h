#define ESPPL_MAC_LEN 6
#define ESPPL_SSID_LEN 33
#define ESPPL_CHANNEL_MIN 1
#define ESPPL_CHANNEL_MAX 14
#define ESPPL_CHANNEL_DEFAULT 1
#define ESPPL_MANAGEMENT_MAC_HEADER_SIZE 36

/*
 *  * ESP8266 sniffer structures
 *   */
struct RxControl {
      signed rssi: 8;
        unsigned rate: 4;
          unsigned is_group: 1;
            unsigned: 1;
                        unsigned sig_mode: 2;
                          unsigned legacy_length: 12;
                            unsigned damatch0: 1;
                              unsigned damatch1: 1;
                                unsigned bssidmatch0: 1;
                                  unsigned bssidmatch1: 1;
                                    unsigned MCS: 7;
                                      unsigned CWB: 1;
                                        unsigned HT_length: 16;
                                          unsigned Smoothing: 1;
                                            unsigned Not_Sounding: 1;
                                              unsigned: 1;
                                                          unsigned Aggregation: 1;
                                                            unsigned STBC: 2;
                                                              unsigned FEC_CODING: 1;
                                                                unsigned SGI: 1;
                                                                  unsigned rxend_state: 8;
                                                                    unsigned ampdu_cnt: 8;
                                                                      unsigned channel: 4;
                                                                        unsigned: 12;
                                                                                         
};

struct LenSeq {
      uint16_t length;
        uint16_t seq;
          uint8_t  address3[6];
          
};

struct sniffer_buf {
      struct RxControl rx_ctrl;
        uint8_t buf[36];
          uint16_t cnt;
            struct LenSeq lenseq[1];
            
};

struct sniffer_buf2 {
      struct RxControl rx_ctrl;
        uint8_t buf[112];
          uint16_t cnt;
            uint16_t len;
            
};

/* 
 *  * ESPProLib structures 
 *   */
struct esppl_frame_info {
      uint8_t frametype;
        uint8_t framesubtype;
          uint8_t receiveraddr[ESPPL_MAC_LEN];
            uint8_t destinationaddr[ESPPL_MAC_LEN];
              uint8_t transmitteraddr[ESPPL_MAC_LEN];
                uint8_t sourceaddr[ESPPL_MAC_LEN];
                  uint8_t bssid[ESPPL_MAC_LEN];  
                    uint8_t ssid[ESPPL_SSID_LEN];
                      uint8_t ssid_length;
                        unsigned channel;
                          signed rssi;
                            uint16_t seq_num;
                              uint8_t raw[512];
                                uint8_t raw_length;
                                  bool isvalid;
                                  
};

typedef void (*ESPPL_CB_T) (esppl_frame_info *frame);

// - DS Field
// const uint8_t ESPPL_DS_NO     = 0;
// const uint8_t ESPPL_DS_TO     = 1;
// const uint8_t ESPPL_DS_FROM   = 2;
// const uint8_t ESPPL_DS_TOFROM = 3;
//
// // - Frame types
// const uint8_t ESPPL_MANAGEMENT = 0;
// const uint8_t ESPPL_CONTROL    = 1;
// const uint8_t ESPPL_DATA       = 2;
//
// // - Frame subtypes
// const uint8_t ESPPL_MANAGEMENT_ASSOCIATION_REQUEST    = 0;
// const uint8_t ESPPL_MANAGEMENT_ASSOCIATION_RESPONSE   = 1;
// const uint8_t ESPPL_MANAGEMENT_REASSOCIATION_REQUEST  = 2;
// const uint8_t ESPPL_MANAGEMENT_REASSOCIATION_RESPONSE = 3;
// const uint8_t ESPPL_MANAGEMENT_PROBE_REQUEST          = 4;
// const uint8_t ESPPL_MANAGEMENT_PROBE_RESPONSE         = 5;
// const uint8_t ESPPL_MANAGEMENT_TIMMING_ADVERTISEMENT  = 6;
// const uint8_t ESPPL_MANAGEMENT_RESERVED1              = 7;
// const uint8_t ESPPL_MANAGEMENT_BEACON                 = 8;
// const uint8_t ESPPL_MANAGEMENT_ATIM                   = 9;
// const uint8_t ESPPL_MANAGEMENT_DISASSOCIATION         = 10;
// const uint8_t ESPPL_MANAGEMENT_AUTHENTICATION         = 11;
// const uint8_t ESPPL_MANAGEMENT_DEAUTHENTICATION       = 12;
// const uint8_t ESPPL_MANAGEMENT_ACTION                 = 13;
// const uint8_t ESPPL_MANAGEMENT_ACTION_NO_ACK          = 14;
// const uint8_t ESPPL_MANAGEMENT_RESERVED2              = 15;
//
// const uint8_t ESPPL_CONTROL_RESERVED1                 = 0;
// const uint8_t ESPPL_CONTROL_RESERVED2                 = 1;
// const uint8_t ESPPL_CONTROL_RESERVED3                 = 2;
// const uint8_t ESPPL_CONTROL_RESERVED4                 = 3;
// const uint8_t ESPPL_CONTROL_RESERVED5                 = 4;
// const uint8_t ESPPL_CONTROL_RESERVED6                 = 5;
// const uint8_t ESPPL_CONTROL_RESERVED7                 = 6;
// const uint8_t ESPPL_CONTROL_CONTROL_WRAPPER           = 7;
// const uint8_t ESPPL_CONTROL_BLOCK_ACK_REQUEST         = 8;
// const uint8_t ESPPL_CONTROL_BLOCK_ACK                 = 9;
// const uint8_t ESPPL_CONTROL_PS_POLL                   = 10;
// const uint8_t ESPPL_CONTROL_RTS                       = 11;
// const uint8_t ESPPL_CONTROL_CTS                       = 12;
// const uint8_t ESPPL_CONTROL_ACK                       = 13;
// const uint8_t ESPPL_CONTROL_CF_END                    = 14;
// const uint8_t ESPPL_CONTROL_CF_END_CF_ACK             = 15;
//
// const uint8_t ESPPL_DATA_DATA                         = 0;
// const uint8_t ESPPL_DATA_DATA_CF_ACK                  = 1;
// const uint8_t ESPPL_DATA_DATA_CF_POLL                 = 2;
// const uint8_t ESPPL_DATA_DATA_CF_ACK_CF_POLL          = 3;
// const uint8_t ESPPL_DATA_NULL                         = 4;
// const uint8_t ESPPL_DATA_CF_ACK                       = 5;
// const uint8_t ESPPL_DATA_CF_POLL                      = 6;
// const uint8_t ESPPL_DATA_CF_ACK_CF_POLL               = 7;
// const uint8_t ESPPL_DATA_QOS_DATA                     = 8;
// const uint8_t ESPPL_DATA_QOS_DATA_CF_ACK              = 9;
// const uint8_t ESPPL_DATA_QOS_DATA_CF_ACK_CF_POLL      = 10;
// const uint8_t ESPPL_DATA_QOS_NULL                     = 11;
// const uint8_t ESPPL_DATA_RESERVED1                    = 12;
// const uint8_t ESPPL_DATA_QOS_CF_POLL                  = 13;
// const uint8_t ESPPL_DATA_QOS_CF_ACK_CF_POLL           = 14;
//
// //TODO: Reserved
