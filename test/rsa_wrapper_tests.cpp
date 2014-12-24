// Test code to get rsa public key encryption working

#ifndef RSA_WRAPPERS_TESTS_H
#define RSA_WRAPPERS_TESTS_H

#include "../src/rsa_wrappers.h"
#include <openssl/rsa.h>
#include <string.h>
#include "test_helpers.cpp"

int rsa_wrapper_basic()
{
    int status = EXIT_SUCCESS;
    unsigned char* sig;
    unsigned int sig_len;
    bool verified;

    // create message
    const char* msg = "Hello, is it me you're looking for?";

    // get key pair
    RSA* priv;
    RSA* pub;
    status = RSA_wrappers::generate_rsa_key(priv);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_test: Error in generate_rsa_key: %d\n", status);
        goto exit;
    }

    status = RSA_wrappers::create_public_key(priv, pub);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_test: Error in create_public_key: %d\n", status);
        goto exit;
    }

    // create message signature
    status = RSA_wrappers::create_signed_digest(priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_test: Error in create_signed_digest: %d\n", status);
        goto exit;
    }

    // Test verification
    verified = RSA_wrappers::verify_signed_digest(pub, (unsigned char*)msg, strlen(msg), sig, sig_len);
    if (verified != true)
    {
        fprintf(stderr, "rsa_wrapper_test: Failed to validate signature\n");
        status = EXIT_FAILURE;
        goto exit;
    }

exit:
    RSA_free(priv);
    RSA_free(pub);
    free(sig);

    return status;
}

void rsa_wrapper_tests(unsigned int& module_count, unsigned int& module_fails)
{
    run_test_func(rsa_wrapper_basic, EXIT_SUCCESS, "rsa_wrapper_basic", module_count, module_fails);
}
#endif
