// Test code to get rsa public key encryption working

#ifndef RSA_WRAPPERS_TESTS_H
#define RSA_WRAPPERS_TESTS_H

#include "../src/rsa_wrappers.h"
#include <string.h>
#include "test_helpers.cpp"

// signed by private, verified by public
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
        fprintf(stderr, "rsa_wrapper_basic: Error in generate_rsa_key: %d\n", status);
        goto exit;
    }

    status = RSA_wrappers::create_public_key(priv, pub);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_basic: Error in create_public_key: %d\n", status);
        goto exit;
    }

    // create message signature
    status = RSA_wrappers::create_signed_digest(priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_basic: Error in create_signed_digest: %d\n", status);
        goto exit;
    }

    // Test verification
    verified = RSA_wrappers::verify_signed_digest(pub, (unsigned char*)msg, strlen(msg), sig, sig_len);
    if (verified != true)
    {
        fprintf(stderr, "rsa_wrapper_basic: Failed to validate signature\n");
        status = EXIT_FAILURE;
        goto exit;
    }

exit:
    RSA_free(priv);
    RSA_free(pub);
    free(sig);

    return status;
}

// signed by private, failed verification by wrong public key
int rsa_wrapper_wrong_pub_key()
{
    int status = EXIT_SUCCESS;
    unsigned char* sig;
    unsigned int sig_len;
    bool verified;

    // create message
    const char* msg = "It Came Upon A Midnight Clear";

    // get key pair
    RSA* priv;
    RSA* pub;
    status = RSA_wrappers::generate_rsa_key(priv);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_wrong_pub_key: Error in generate_rsa_key: %d\n", status);
        goto exit;
    }

    status = RSA_wrappers::create_public_key(priv, pub);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_wrong_pub_key: Error in create_public_key: %d\n", status);
        goto exit;
    }

    // create message signature
    status = RSA_wrappers::create_signed_digest(priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_wrong_pub_key: Error in create_signed_digest: %d\n", status);
        goto exit;
    }

    // get wrong keypair
    RSA* wrong_priv;
    RSA* wrong_pub;
    status = RSA_wrappers::generate_rsa_key(wrong_priv);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_wrong_pub_key: Error in generate_rsa_key: %d\n", status);
        goto exit;
    }

    status = RSA_wrappers::create_public_key(wrong_priv, wrong_pub);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_wrong_pub_key: Error in create_public_key: %d\n", status);
        goto exit;
    }

    // Test verification
    verified = RSA_wrappers::verify_signed_digest(wrong_pub, (unsigned char*)msg, strlen(msg), sig, sig_len);
    if (verified == true)
    {
        fprintf(stderr, "rsa_wrapper_wrong_pub_key: Incorrectly validated signature with different public key\n");
        status = EXIT_FAILURE;
        goto exit;
    }

exit:
    RSA_free(priv);
    RSA_free(pub);
    free(sig);

    return status;
}

// signed by private, failed verification by wrong private key
int rsa_wrapper_wrong_priv_key()
{
    int status = EXIT_SUCCESS;
    unsigned char* sig;
    unsigned int sig_len;
    bool verified;

    // create message
    const char* msg = "Sleighbells in the air, beauty everywhere. Yule tide by the fireside and joyful memories there. Christmas time is here.";

    // get key pair
    RSA* priv;
    RSA* pub;
    status = RSA_wrappers::generate_rsa_key(priv);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_wrong_priv_key: Error in generate_rsa_key: %d\n", status);
        goto exit;
    }

    status = RSA_wrappers::create_public_key(priv, pub);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_wrong_priv_key: Error in create_public_key: %d\n", status);
        goto exit;
    }

    // create message signature
    status = RSA_wrappers::create_signed_digest(priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_wrong_priv_key: Error in create_signed_digest: %d\n", status);
        goto exit;
    }

    // get wrong keypair
    RSA* wrong_priv;
    RSA* wrong_pub;
    status = RSA_wrappers::generate_rsa_key(wrong_priv);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_wrong_priv_key: Error in generate_rsa_key: %d\n", status);
        goto exit;
    }

    status = RSA_wrappers::create_public_key(wrong_priv, wrong_pub);
    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "rsa_wrapper_wrong_priv_key: Error in create_public_key: %d\n", status);
        goto exit;
    }

    // Test verification
    verified = RSA_wrappers::verify_signed_digest(wrong_priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
    if (verified == true)
    {
        fprintf(stderr, "rsa_wrapper_wrong_priv_key: Incorrectly validated signature with different public key\n");
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
    run_test_func(rsa_wrapper_wrong_pub_key, EXIT_SUCCESS, "rsa_wrapper_wrong_pub_key", module_count, module_fails);
    run_test_func(rsa_wrapper_wrong_priv_key, EXIT_SUCCESS, "rsa_wrapper_wrong_priv_key", module_count, module_fails);
}
#endif
