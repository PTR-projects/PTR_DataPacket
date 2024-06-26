#include <stdint.h>
#include <stdio.h>
#include <DataPacket_definitions.h>

static uint16_t crc16(uint8_t *data, uint16_t length);
static void encrypt_msg(kppacket_t * msg);
static uint8_t getRandomByte();

// Precomputed CRC16 table using polynomial 0x8005
static const uint16_t crc16_table[256] = {
    0x0000, 0x8005, 0x800f, 0x000a, 0x801b, 0x001e, 0x0014, 0x8011,
    0x8033, 0x0036, 0x003c, 0x8039, 0x0028, 0x802d, 0x8027, 0x0022,
    0x8063, 0x0066, 0x006c, 0x8069, 0x0078, 0x807d, 0x8077, 0x0072,
    0x0050, 0x8055, 0x805f, 0x005a, 0x804b, 0x004e, 0x0044, 0x8041,
    0x80c3, 0x00c6, 0x00cc, 0x80c9, 0x00d8, 0x80dd, 0x80d7, 0x00d2,
    0x00f0, 0x80f5, 0x80ff, 0x00fa, 0x80eb, 0x00ee, 0x00e4, 0x80e1,
    0x00a0, 0x80a5, 0x80af, 0x00aa, 0x80bb, 0x00be, 0x00b4, 0x80b1,
    0x8093, 0x0096, 0x009c, 0x8099, 0x0088, 0x808d, 0x8087, 0x0082,
    0x8183, 0x0186, 0x018c, 0x8189, 0x0198, 0x819d, 0x8197, 0x0192,
    0x01b0, 0x81b5, 0x81bf, 0x01ba, 0x81ab, 0x01ae, 0x01a4, 0x81a1,
    0x01e0, 0x81e5, 0x81ef, 0x01ea, 0x81fb, 0x01fe, 0x01f4, 0x81f1,
    0x81d3, 0x01d6, 0x01dc, 0x81d9, 0x01c8, 0x81cd, 0x81c7, 0x01c2,
    0x0140, 0x8145, 0x814f, 0x014a, 0x815b, 0x015e, 0x0154, 0x8151,
    0x8173, 0x0176, 0x017c, 0x8179, 0x0168, 0x816d, 0x8167, 0x0162,
    0x8123, 0x0126, 0x012c, 0x8129, 0x0138, 0x813d, 0x8137, 0x0132,
    0x0110, 0x8115, 0x811f, 0x011a, 0x810b, 0x010e, 0x0104, 0x8101,
    0x8303, 0x0306, 0x030c, 0x8309, 0x0318, 0x831d, 0x8317, 0x0312,
    0x0330, 0x8335, 0x833f, 0x033a, 0x832b, 0x032e, 0x0324, 0x8321,
    0x0360, 0x8365, 0x836f, 0x036a, 0x837b, 0x037e, 0x0374, 0x8371,
    0x8353, 0x0356, 0x035c, 0x8359, 0x0348, 0x834d, 0x8347, 0x0342,
    0x03c0, 0x83c5, 0x83cf, 0x03ca, 0x83db, 0x03de, 0x03d4, 0x83d1,
    0x83f3, 0x03f6, 0x03fc, 0x83f9, 0x03e8, 0x83ed, 0x83e7, 0x03e2,
    0x83a3, 0x03a6, 0x03ac, 0x83a9, 0x03b8, 0x83bd, 0x83b7, 0x03b2,
    0x0390, 0x8395, 0x839f, 0x039a, 0x838b, 0x038e, 0x0384, 0x8381,
    0x0280, 0x8285, 0x828f, 0x028a, 0x829b, 0x029e, 0x0294, 0x8291,
    0x82b3, 0x02b6, 0x02bc, 0x82b9, 0x02a8, 0x82ad, 0x82a7, 0x02a2,
    0x82e3, 0x02e6, 0x02ec, 0x82e9, 0x02f8, 0x82fd, 0x82f7, 0x02f2,
    0x02d0, 0x82d5, 0x82df, 0x02da, 0x82cb, 0x02ce, 0x02c4, 0x82c1,
    0x8243, 0x0246, 0x024c, 0x8249, 0x0258, 0x825d, 0x8257, 0x0252,
    0x0270, 0x8275, 0x827f, 0x027a, 0x826b, 0x026e, 0x0264, 0x8261,
    0x0220, 0x8225, 0x822f, 0x022a, 0x823b, 0x023e, 0x0234, 0x8231,
    0x8213, 0x0216, 0x021c, 0x8219, 0x0208, 0x820d, 0x8207, 0x0202
};

#if TARGET_ESP
#include "esp_random.h"
// Hardware AES API

#else
// Software AES API
#endif


void DataPacket_init(){
    #if TARGET_ESP

    #else
    srand(134);
    #endif
}

int8_t DataPacket_build_msg(kppacket_t * msg, msg_type_e msg_type, bool encrypted, uint8_t sender_id, uint8_t dest_id, uint16_t packet_no, void * payload, uint8_t payload_len){
    // Checks
    if(payload_len > (255 - sizeof(kppacket_header_t)))
        return -1;
    
    if(payload == NULL)
        return -1;
    
    if(msg == NULL)
        return -1;

    packet_id_t packet_id;
    packet_id.msg_ver    = 0;
    packet_id.retransmit = 0;
    packet_id.encoded    = encrypted;
    packet_id.msg_type   = msg_type;

    msg->header.packet_id = packet_id;
    
    msg->header.sender_id = sender_id;
    msg->header.dest_id   = dest_id;
    msg->header.packet_no = packet_no;
    
    msg->header.crc16 = 0;

    // Check payload length
    uin8_t expected_payload_len = 0;
    uin8_t expected_header_len = 0;
    switch(msg_type){
        case PACKET_HEARTBEAT:
            expected_payload_len = 0;
            expected_header_len  = sizeof(kppacket_header_t);
            break;
        case PACKET_LEGACY_FULL:
            expected_payload_len = sizeof(kppacket_payload_legacyfull_t);
            expected_header_len  = sizeof(kppacket_legacyheader_t);
            break;
        case PACKET_SENSORS:
            expected_payload_len = sizeof(kppacket_payload_rocket_meas_t);
            expected_header_len  = sizeof(kppacket_header_t);
            break;
        case PACKET_ADCS:
            expected_payload_len = sizeof(kppacket_payload_rocket_ADCS_t);
            expected_header_len  = sizeof(kppacket_header_t);
            break;
        case PACKET_TRACKER:
            expected_payload_len = sizeof(kppacket_payload_rocket_tracker_t);
            expected_header_len  = sizeof(kppacket_header_t);
            break;
        case PACKET_CUSTOM_8B:
            expected_payload_len = 8;
            expected_header_len  = sizeof(kppacket_header_t);
            break;
        case PACKET_CUSTOM_16B:
            expected_payload_len = 16;
            expected_header_len  = sizeof(kppacket_header_t);
            break;
        case PACKET_CUSTOM_32B:
            expected_payload_len = 32;
            expected_header_len = sizeof(kppacket_header_t);
            break;
        case PACKET_CUSTOM_64B:
            expected_payload_len = 64;
            expected_header_len  = sizeof(kppacket_header_t);
            break;
        case PACKET_CUSTOM_128B:
            expected_payload_len = 128;
            expected_header_len  = sizeof(kppacket_header_t);
            break;
        case PACKET_CUSTOM_240B:
            expected_payload_len = 240;
            expected_header_len  = sizeof(kppacket_header_t);
            break;
    }

    if(expected_payload_len != payload_len)
        return -1;

    uint8_t payload_offset = 0;
    if(encrypted){
        payload_offset = 4;
    }
    if(payload_len != 0)
        memcpy(msg->payload + payload_offset, payload, payload_len);

    msg->packet_len = expected_payload_len + expected_header_len + payload_offset;
    
    // Calculate payload CRC16
    msg.crc16 = crc16(msg->payload + payload_offset, expected_payload_len);

    if(encrypted){
        encrypt_msg(msg);
    }

    return 0;
}

static uint16_t crc16(uint8_t *data, uint16_t length) {
    uint16_t crc = 0x0000;  // Initial value

    for (size_t i = 0; i < length; i++) {
        uint8_t table_index = (crc >> 8) ^ data[i];
        crc = (crc << 8) ^ crc16_table[table_index];
    }

    return crc;
}

static void encrypt_msg(kppacket_t * msg){

    uint8_t * enc_header_ptr = msg->payload;
    struct {
        uint16_t random_2byte;
        uint16_t const_2byte;
    } encryption_header;

    encryption_header.const_2byte = 0xabcd;
    encryption_header.random_2byte = getRandomByte() | (getRandomByte()<<8);

    // Add security header at the beginning of the payload
    memcpy(enc_header_ptr, encryption_header, sizeof(encryption_header));


    // Encryption Magic
    // TODO

}

static uint8_t getRandomByte(){
    #if TARGET_ESP
    // use ESP random generator
    return esp_random % 255;

    #else
    // Use Std C Pseudo Random Generator
    return rand() % 255;
    #endif
    
}