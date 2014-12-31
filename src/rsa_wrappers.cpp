// Cameron Bielstein, 12/23/14
// rsa_wrappers.cpp
// Wrapper functions for OpenSSL's RSA encryption and verification algorithms

#include "rsa_wrappers.h"

int RSA_wrappers::generate_rsa_key(RSA*& rsa)
{
    int status = RSA_wrappers::SUCCESS;

    // we're creating a NEW key at rsa
    rsa = RSA_new();

    // set e = 3. This is not proven to be less secure than larger numbers with PKCS padding used by OpenSSL
    // and this gives speed increases important for low-end devices
    BIGNUM* e = BN_new();
    status = BN_add(e, BN_value_one(), BN_value_one());
    if (status != 1) { fprintf(stderr, "Failed on BN_add in generate_rsa_key\n"); return RSA_wrappers::GENERAL_FAILURE; }
    status = BN_add(e, e, BN_value_one());
    if (status != 1) { fprintf(stderr, "Failed on BN_add in generate_rsa_key\n"); return RSA_wrappers::GENERAL_FAILURE; }

    // seed time
    srand(time(NULL));

    // generate key
    status = RSA_generate_key_ex(rsa, 1024, e, NULL);
    if (status < 0 )
    {
        fprintf(stderr, "RSA_generate_key_ex failed. Returned %d, %s\n", status, ERR_error_string(ERR_get_error(), NULL));
        return RSA_wrappers::GENERAL_FAILURE;
    }

    return RSA_wrappers::SUCCESS;
}

int RSA_wrappers::create_public_key(const RSA* priv_key, RSA*& pub_key)
{
    if (priv_key == nullptr)
    {
        fprintf(stderr, "Passed a null argument in create_public_key(%p, %p)\n", priv_key, pub_key);
        return RSA_wrappers::NULL_ARG;
    }

    // we're creating a NEW key at pub_key
    pub_key = RSA_new();

    // copy over public elements
    pub_key->n = BN_dup(priv_key->n);
    pub_key->e = BN_dup(priv_key->e);

    return RSA_wrappers::SUCCESS;
}

int RSA_wrappers::create_signed_digest(RSA* priv_key, const unsigned char* msg,
                                       const unsigned int msg_length, unsigned char*& sig,
                                       unsigned int& sig_len)
{
    int status = RSA_wrappers::SUCCESS;

    if (priv_key == NULL || msg == NULL)
    {
        fprintf(stderr, "NULL args: create_signed_digest(%p, %p, %u, %p, %d)\n", priv_key, msg, msg_length, sig, sig_len);
        return RSA_wrappers::NULL_ARG;
    }

    // hash the message
    unsigned char* digest = SHA1((unsigned char*)msg, msg_length, NULL);
    if (digest == NULL)
    {
        fprintf(stderr, "SHA1 failed in create_signed_digest. Returned NULL\n");
        return RSA_wrappers::GENERAL_FAILURE;
    }

    // sign that digest!
    sig = (unsigned char*)malloc(RSA_size(priv_key));
    status = RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sig, &sig_len, priv_key);
    if (status != 1)
    {
        fprintf(stderr, "RSA_sign failed in create_signed_digest. Returned %d, %s\n", status, ERR_error_string(ERR_get_error(), NULL));
        return RSA_wrappers::GENERAL_FAILURE;
    }

    return RSA_wrappers::SUCCESS;
}

int RSA_wrappers::verify_signed_digest(RSA* pub_key, const unsigned char* msg,
                                       const unsigned int msg_length, const unsigned char* sig,
                                       const unsigned int sig_len)
{
    unsigned char* digest = SHA1((unsigned char*)msg, msg_length, NULL);
    if (digest == NULL)
    {
        fprintf(stderr, "SHA1 failed in create_signed_digest. Returned NULL\n");
        return RSA_wrappers::GENERAL_FAILURE;
    }

    int verified = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, (unsigned char *)sig, sig_len, pub_key);

    return (verified == 1) ? 1 : 0;
}

int RSA_wrappers::is_private_key(const RSA* key)
{
    if (key == nullptr)
    {
        fprintf(stderr, "is_private_key: passed null argument\n");
        return RSA_wrappers::NULL_ARG;
    }
    return (key->d == nullptr) ? 0 : 1;
}

int RSA_wrappers::encrypt(RSA* key, const unsigned char* msg, const unsigned int& msg_len, unsigned char*& result, unsigned int* result_len)
{
    int status = RSA_wrappers::SUCCESS;
    if (result_len != nullptr)
    {
        *result_len = 0;
    }

    // msg needs to be no longer than max message length
    if (msg_len > MAX_MESSAGE_LENGTH(key))
    {
        fprintf(stderr, "encrypt: Message was too long. Length: %d, max length: %d\n", msg_len, MAX_MESSAGE_LENGTH(key));
        return RSA_wrappers::INVALID_INPUT;
    }

    // allocate the result pointer
    result = (unsigned char*)malloc(RSA_size(key));
    if (result == nullptr)
    {
        fprintf(stderr, "encrypt: malloc failed to allocate result pointer of size %d\n", RSA_size(key));
        return RSA_wrappers::GENERAL_FAILURE;
    }

    // seed random number generator
    srand(time(NULL));

    status = RSA_wrappers::is_private_key(key);
    if (status == 1)
    {
        // encrypt private
        status = RSA_private_encrypt(msg_len, msg, result, key, RSA_PKCS1_PADDING);
        if (status < 0)
        {
            fprintf(stderr, "encrypt: RSA_private_encrypt failed, returned status %d with error %s\n", status, ERR_error_string(ERR_get_error(), NULL));
            goto exit_failure;
        }
    }
    else if (status == 0)
    {
        // encrypt public
        status = RSA_public_encrypt(msg_len, msg, result, key, RSA_PKCS1_PADDING);
        if (status < 0)
        {
            fprintf(stderr, "encrypt: RSA_public_encrypt failed, returned status %d with error %s\n", status, ERR_error_string(ERR_get_error(), NULL));
            goto exit_failure;
        }
    }
    else
    {
        // error in is_private_key, cleanup and get out
        goto exit_failure;
    }

    // update result_len from above
    if (result_len != nullptr)
    {
        *result_len = status;
    }

    return RSA_wrappers::SUCCESS;

    exit_failure:
        free(result);
        return status;
}

int RSA_wrappers::decrypt(RSA* key, const unsigned char* msg, unsigned char*& result, unsigned int* result_len)
{
    int status = RSA_wrappers::SUCCESS;
    if (result_len != nullptr)
    {
        *result_len = 0;
    }

    // allocate the result pointer
    result = (unsigned char*)malloc(RSA_size(key));
    if (result == nullptr)
    {
        fprintf(stderr, "encrypt: malloc failed to allocate result pointer of size %d\n", RSA_size(key));
        return RSA_wrappers::GENERAL_FAILURE;
    }

    status = RSA_wrappers::is_private_key(key);
    if (status == 1)
    {
        // encrypt private
        status = RSA_private_decrypt(RSA_size(key), msg, result, key, RSA_PKCS1_PADDING);
        if (status < 0)
        {
            fprintf(stderr, "decrypt: RSA_private_decrypt failed, returned status %d with error %s\n", status, ERR_error_string(ERR_get_error(), NULL));
            goto exit_failure;
        }
    }
    else if (status == 0)
    {
        // encrypt public
        status = RSA_public_decrypt(RSA_size(key), msg, result, key, RSA_PKCS1_PADDING);
        if (status < 0)
        {
            fprintf(stderr, "decrypt: RSA_public_decrypt failed, returned status %d with error %s\n", status, ERR_error_string(ERR_get_error(), NULL));
            goto exit_failure;
        }
    }
    else
    {
        // error in is_private_key, cleanup and get out
        goto exit_failure;
    }

    // update result_len from above
    if (result_len != nullptr)
    {
        *result_len = status;
    }

    return RSA_wrappers::SUCCESS;

    exit_failure:
        free(result);
        return status;
}
