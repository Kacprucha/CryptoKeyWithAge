#include <stdint.h>

void handle_get_random (const uint8_t *request_data, uint16_t request_len);
void handle_get_public_key(const uint8_t *request_data, uint16_t request_len);
void handle_ecdh_request(const uint8_t *request_data, uint16_t request_len);