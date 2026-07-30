#include <stdint.h>
#include<stdbool.h>

void handle_get_random (const uint8_t *request_data, uint16_t request_len);
void handle_get_public_key(const uint8_t *request_data, uint16_t request_len);
void handle_ecdh_request(const uint8_t *request_data, uint16_t request_len, bool skip_tup_check);
void handle_get_i2c_time(const uint8_t *req_data, uint16_t req_len); 