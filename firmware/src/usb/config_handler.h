#include <stdint.h>
#define CMD_CONFIG_OP  0x10

void handle_config_op(const uint8_t *req_data, uint16_t req_len);

void handle_gen_key(const uint8_t *req_data, uint16_t req_len);