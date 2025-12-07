#include <stdio.h>
#include <string.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"

#define MESSAGE_LEN 32

// Helper to print a buffer as hex
static void print_hex(const char *label,
                      const unsigned char *buf,
                      size_t len)
{
    size_t i;

    printf("%s (%zu bytes): ", label, len);
    for (i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
        if (i + 1 < len)
            printf(" ");
    }
    printf("\n");
}

// Helper to print Mbed TLS error codes

static void print_mbedtls_error(const char *msg, int ret)
{
    char errbuf[128];
    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
    fprintf(stderr, "%s: -0x%04X (%s)\n", msg, (unsigned int)(-ret), errbuf);
}

int main(void)
{
    int ret = 0;
    int overall_status = 0;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;

    unsigned char message[MESSAGE_LEN];
    unsigned char tampered_message[MESSAGE_LEN];

    unsigned char hash[32];          // Original Message
    unsigned char tampered_hash[32]; // Tempered Message

    unsigned char signature[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;

    // Initialization

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    // Seeding the CTR-DRBG with entropy

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                mbedtls_entropy_func,
                                &entropy,
                                NULL,
                                0);
    if (ret != 0)
    {
        print_mbedtls_error("Failed to seed CTR_DRBG", ret);
        overall_status = 1;
        goto cleanup;
    }

    // Setting up PK context for an EC key

    {
        const mbedtls_pk_info_t *pk_info =
            mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
        if (pk_info == NULL)
        {
            fprintf(stderr, "Failed to get PK info for EC key.\n");
            overall_status = 1;
            goto cleanup;
        }

        ret = mbedtls_pk_setup(&pk, pk_info);
        if (ret != 0)
        {
            print_mbedtls_error("Failed to set up PK context", ret);
            overall_status = 1;
            goto cleanup;
        }
    }

    // Generating EC keypair

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                              mbedtls_pk_ec(pk),
                              mbedtls_ctr_drbg_random,
                              &ctr_drbg);
    if (ret != 0)
    {
        print_mbedtls_error("Failed to generate EC keypair", ret);
        overall_status = 1;
        goto cleanup;
    }

    printf("Generated EC keypair\n");

    // Generating a random message

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, message, sizeof(message));
    if (ret != 0)
    {
        print_mbedtls_error("Failed to generate random message", ret);
        overall_status = 1;
        goto cleanup;
    }

    print_hex("Random message", message, sizeof(message));

    // Computing SHA-256

    ret = mbedtls_sha256(message, sizeof(message), hash, 0);
    if (ret != 0)
    {
        print_mbedtls_error("Failed to compute SHA-256 of message", ret);
        overall_status = 1;
        goto cleanup;
    }

    print_hex("SHA-256(message)", hash, sizeof(hash));

    // Signing the hash with the private key

    ret = mbedtls_pk_sign(&pk,
                          MBEDTLS_MD_SHA256,
                          hash,
                          sizeof(hash),
                          signature,
                          sizeof(signature),
                          &sig_len,
                          mbedtls_ctr_drbg_random,
                          &ctr_drbg);
    if (ret != 0)
    {
        print_mbedtls_error("Failed to sign hash", ret);
        overall_status = 1;
        goto cleanup;
    }

    printf("Signature generated successfully.\n");
    print_hex("Signature", signature, sig_len);

    // Verifying the signature against the original message

    ret = mbedtls_pk_verify(&pk,
                            MBEDTLS_MD_SHA256,
                            hash,
                            sizeof(hash),
                            signature,
                            sig_len);
    if (ret != 0)
    {
        print_mbedtls_error("ERROR: verification of valid signature failed", ret);
        overall_status = 1;
        goto cleanup;
    }

    printf("Verification of valid signature: SUCCESS.\n");

    // Tempering the original message

    memcpy(tampered_message, message, sizeof(message));
    tampered_message[0] ^= 0x01; // Changing the first byte

    print_hex("Tampered message", tampered_message, sizeof(tampered_message));

    // Computing SHA-256 over the tampered message

    ret = mbedtls_sha256(tampered_message,
                         sizeof(tampered_message),
                         tampered_hash,
                         0);
    if (ret != 0)
    {
        print_mbedtls_error("Failed to compute SHA-256 of tampered message", ret);
        overall_status = 1;
        goto cleanup;
    }

    print_hex("SHA-256(tampered_message)", tampered_hash, sizeof(tampered_hash));

    // Verifying the original signature against the Wrong Hash

    ret = mbedtls_pk_verify(&pk,
                            MBEDTLS_MD_SHA256,
                            tampered_hash,
                            sizeof(tampered_hash),
                            signature,
                            sig_len);
    if (ret == 0)
    {

        fprintf(stderr,
                "ERROR: verification of tampered message unexpectedly SUCCEEDED.\n");
        overall_status = 1;
        goto cleanup;
    }
    else
    {
        printf("Verification with tampered message correctly FAILED.\n");
    }

cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return overall_status;
}
