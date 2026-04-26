/*
 * host/test_ecdh_verify.c
 *
 * Test of ECDH correctness between host and device.
 *
 * Użycie:
 *   ./test_ecdh_verify [port] [slot]
 *   ./test_ecdh_verify /dev/ttyACM0 0
 *   ./test_ecdh_verify /dev/ttyACM0 2
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "device.h"
#include "protocol.h"

#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

static void print_mbedtls_error(const char *func, int ret) 
{
    char errbuf[256];
    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
    fprintf(stderr, "%s FAIL: -0x%04x – %s\n", func, (unsigned)(-ret), errbuf);
}

static void secure_zero(void *ptr, size_t len) 
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

static void print_hex(const char *label, const uint8_t *buf, size_t len) 
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main(int argc, char *argv[]) 
{
    const char *port = (argc > 1) ? argv[1] : "/dev/ttyACM0";

    uint8_t slot = 0;
    if (argc > 2) 
    {
        int slot_arg = atoi(argv[2]);
        
        if (slot_arg < 0 || slot_arg > 7) 
        {
            fprintf(stderr, "Błąd: slot musi być w zakresie 0-7 (podano: %d)\n", slot_arg);
            return 1;
        }
        
        slot = (uint8_t)slot_arg;
    }

    printf("=== test_ecdh_verify: port=%s slot=%d ===\n", port, slot);

    int fd = device_open(port);
    if (fd < 0) 
    {
        perror("device_open");
        return 1;
    }

    int ret;
    int exit_code = 1;

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point device_point; 
    mbedtls_ecp_point result_point; 
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_init(&device_point);
    mbedtls_ecp_point_init(&result_point);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) 
    {
        print_mbedtls_error("ctr_drbg_seed", ret);
        goto cleanup;
    }

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) 
    {
        print_mbedtls_error("ecp_group_load", ret);
        goto cleanup;
    }

    uint8_t  device_pub_raw[64];
    uint16_t pub_len = 0;

    if (device_send_cmd(fd, CMD_GET_PUBLIC_KEY, &slot, 1, NULL, device_pub_raw, &pub_len) != 0 || pub_len != 64) 
    {
        fprintf(stderr, "GET_PUBLIC_KEY FAIL (slot %d) – does the slot have a generated key?\n", slot);
        goto cleanup;
    }

    print_hex("Device pub X", device_pub_raw, 32);
    print_hex("Device pub Y", device_pub_raw + 32, 32);

    uint8_t device_pub_65[65];
    device_pub_65[0] = 0x04;
    memcpy(device_pub_65 + 1, device_pub_raw, 64);

    ret = mbedtls_ecp_point_read_binary(&grp, &device_point, device_pub_65, 65);
    if (ret != 0) 
    {
        print_mbedtls_error("ecp_point_read_binary(device_pub)", ret);
        goto cleanup;
    }

    ret = mbedtls_ecp_check_pubkey(&grp, &device_point);
    if (ret != 0) 
    {
        print_mbedtls_error("ecp_check_pubkey(device_point)", ret);
        goto cleanup;
    }

    ret = mbedtls_ecp_gen_privkey(&grp, &d, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) 
    {
        print_mbedtls_error("ecp_gen_privkey", ret);
        goto cleanup;
    }

    ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) 
    {
        print_mbedtls_error("ecp_mul(Q = d*G)", ret);
        goto cleanup;
    }

    uint8_t  eph_pub_65[65];
    size_t   eph_pub_olen = 0;

    ret = mbedtls_ecp_point_write_binary(&grp, &Q,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &eph_pub_olen,
                                          eph_pub_65, sizeof(eph_pub_65));
    if (ret != 0 || eph_pub_olen != 65) 
    {
        print_mbedtls_error("ecp_point_write_binary(Q)", ret);
        goto cleanup;
    }

    const uint8_t *eph_pub_64 = eph_pub_65 + 1; 

    print_hex("Ephemeral pub X", eph_pub_64, 32);
    print_hex("Ephemeral pub Y", eph_pub_64 + 32, 32);

    ret = mbedtls_ecp_mul(&grp, &result_point, &d, &device_point, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) 
    {
        print_mbedtls_error("ecp_mul(soft ECDH)", ret);
        goto cleanup;
    }

    uint8_t result_65[65];
    size_t  result_olen = 0;

    ret = mbedtls_ecp_point_write_binary(&grp, &result_point,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &result_olen,
                                          result_65, sizeof(result_65));
    if (ret != 0 || result_olen != 65) {
        print_mbedtls_error("ecp_point_write_binary(result)", ret);
        goto cleanup;
    }

    uint8_t soft_shared[32];
    memcpy(soft_shared, result_65 + 1, 32);

    secure_zero(result_65, sizeof(result_65));

    uint8_t  ecdh_payload[65];
    ecdh_payload[0] = slot;
    memcpy(ecdh_payload + 1, eph_pub_64, 64);

    uint8_t  hw_shared[32];
    uint16_t hw_len = 0;

    printf("[!] TUP: Please press button to confirm the ECDH operation...\n");

    if (device_send_cmd(fd, CMD_ECDH_REQUEST, ecdh_payload, 65, NULL, hw_shared, &hw_len) != 0 || hw_len != 32) 
    {
        fprintf(stderr, "ECDH_REQUEST FAIL (slot %d)\n", slot);
        secure_zero(soft_shared, sizeof(soft_shared));
        goto cleanup;
    }

    print_hex("Soft shared secret", soft_shared, 32);
    print_hex("HW   shared secret", hw_shared,   32);

    int match = (memcmp(soft_shared, hw_shared, 32) == 0);

    secure_zero(soft_shared, sizeof(soft_shared));
    secure_zero(hw_shared, sizeof(hw_shared));

    if (match) 
    {
        printf("ECDH OK – results match!\n");
        printf("Private key in the slot %d works correctly.\n", slot);
        exit_code = 0;
    } 
    else 
    {
        fprintf(stderr, "ECDH MISMATCH! Check the configuration of slot %d.\n", slot);
        exit_code = 1;
    }

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_point_free(&device_point);
    mbedtls_ecp_point_free(&result_point);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    device_close(fd);

    return exit_code;
}