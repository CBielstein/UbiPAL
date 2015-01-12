// Cameron Bielstein, 12/23/14
// rsa_wrappers.cpp
// Wrapper functions for OpenSSL's RSA encryption and verification algorithms

#include "rsa_wrappers.h"

namespace UbiPAL
{
    int RsaWrappers::GenerateRsaKey(RSA*& rsa)
    {
        int status = SUCCESS;

        // we're creating a NEW key at rsa
        rsa = RSA_new();

        // set e = 3. This is not proven to be less secure than larger numbers with PKCS padding used by OpenSSL
        // and this gives speed increases important for low-end devices
        BIGNUM* e = BN_new();
        status = BN_set_bit(e, 0);
        if (status != 1)
        {
            fprintf(stderr, "GenerateRsaKey: Failed on BN_set_bit(e,0) in GenerateRsaKey: %d, %s\n", status, ERR_error_string(ERR_get_error(), NULL));
            status = GENERAL_FAILURE;
            goto exit;
        }

        status = BN_set_bit(e, 1);
        if (status != 1)
        {
            fprintf(stderr, "GenerateRsaKey: Failed on BN_set_bit(e,1) in GenerateRsaKey: %d, %s\n", status, ERR_error_string(ERR_get_error(), NULL));
            status = GENERAL_FAILURE;
            goto exit;
        }

        // seed time
        srand(time(NULL));

        // generate key
        status = RSA_generate_key_ex(rsa, 1024, e, NULL);
        if (status < 0)
        {
            fprintf(stderr, "RSA_generate_key_ex failed. Returned %d, %s\n", status, ERR_error_string(ERR_get_error(), NULL));
            status = GENERAL_FAILURE;
            goto exit;
        }

        status = SUCCESS;

        exit:
            BN_free(e);
            return status;
    }

    int RsaWrappers::CreatePublicKey(const RSA* priv_key, RSA*& pub_key)
    {
        int status = SUCCESS;

        if (priv_key == nullptr)
        {
            fprintf(stderr, "Passed a null argument in CreatePublicKey(%p, %p)\n", priv_key, pub_key);
            status = NULL_ARG;
            goto exit;
        }

        // we're creating a NEW key at pub_key
        pub_key = RSA_new();

        // copy over public elements
        pub_key->n = BN_dup(priv_key->n);
        pub_key->e = BN_dup(priv_key->e);

        exit:
            return status;
    }

    int RsaWrappers::CreateSignedDigest(RSA* priv_key, const unsigned char* msg,
                                        const unsigned int msg_length, unsigned char*& sig,
                                        unsigned int& sig_len)
    {
        int status = SUCCESS;
        unsigned char* digest;

        if (priv_key == NULL || msg == NULL)
        {
            fprintf(stderr, "NULL args: CreateSignedDigest(%p, %p, %u, %p, %d)\n", priv_key, msg, msg_length, sig, sig_len);
            status = NULL_ARG;
            goto exit;
        }

        // hash the message
        digest = SHA1((unsigned char*)msg, msg_length, NULL);
        if (digest == NULL)
        {
            fprintf(stderr, "SHA1 failed in CreateSignedDigest. Returned NULL\n");
            status = GENERAL_FAILURE;
            goto exit;
        }

        // sign that digest!
        sig = (unsigned char*)malloc(RSA_size(priv_key));
        status = RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sig, &sig_len, priv_key);
        if (status != 1)
        {
            fprintf(stderr, "RSA_sign failed in CreateSignedDigest. Returned %d, %s\n", status, ERR_error_string(ERR_get_error(), NULL));
            status = GENERAL_FAILURE;
            goto exit;
        }

        status = SUCCESS;

        exit:
            return status;
    }

    int RsaWrappers::VerifySignedDigest(RSA* pub_key, const unsigned char* msg,
                                        const unsigned int msg_length, const unsigned char* sig,
                                        const unsigned int sig_len)
    {
        unsigned char* digest = SHA1((unsigned char*)msg, msg_length, NULL);
        if (digest == NULL)
        {
            fprintf(stderr, "SHA1 failed in CreateSignedDigest. Returned NULL\n");
            return GENERAL_FAILURE;
        }

        int verified = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, (unsigned char *)sig, sig_len, pub_key);

        return (verified == 1) ? 1 : 0;
    }

    int RsaWrappers::IsPrivateKey(const RSA* key)
    {
        if (key == nullptr)
        {
            fprintf(stderr, "IsPrivateKey: passed null argument\n");
            return NULL_ARG;
        }
        return (key->d == nullptr) ? 0 : 1;
    }

    int RsaWrappers::Encrypt(RSA* key, const unsigned char* msg, const unsigned int& msg_len, unsigned char*& result, unsigned int* result_len)
    {
        int status = SUCCESS;

        if (result_len != nullptr)
        {
            *result_len = 0;
        }

        // msg needs to be no longer than max message length
        if (msg_len > RsaWrappers::MaxMessageLength(key))
        {
            fprintf(stderr, "Encrypt: Message was too long. Length: %d, max length: %d\n", msg_len, RsaWrappers::MaxMessageLength(key));
            status = INVALID_ARG;
            goto exit_failure;
        }

        // allocate the result pointer
        result = (unsigned char*)malloc(RSA_size(key));
        if (result == nullptr)
        {
            fprintf(stderr, "Encrypt: malloc failed to allocate result pointer of size %d\n", RSA_size(key));
            status = GENERAL_FAILURE;
            goto exit_failure;
        }

        // seed random number generator
        srand(time(NULL));

        status = RsaWrappers::IsPrivateKey(key);
        if (status == 1)
        {
            // encrypt private
            status = RSA_private_encrypt(msg_len, msg, result, key, RSA_PKCS1_PADDING);
            if (status < 0)
            {
                fprintf(stderr, "Encrypt: RSA_private_encrypt failed, returned status %d with error %s\n", status, ERR_error_string(ERR_get_error(), NULL));
                goto exit_failure;
            }
        }
        else if (status == 0)
        {
            // encrypt public
            status = RSA_public_encrypt(msg_len, msg, result, key, RSA_PKCS1_PADDING);
            if (status < 0)
            {
                fprintf(stderr, "Encrypt: RSA_public_encrypt failed, returned status %d with error %s\n", status, ERR_error_string(ERR_get_error(), NULL));
                goto exit_failure;
            }
        }
        else
        {
            // error in IsPrivateKey, cleanup and get out
            goto exit_failure;
        }

        // update result_len from above
        if (result_len != nullptr)
        {
            *result_len = status;
        }

        return SUCCESS;

        exit_failure:
            free(result);
            return status;
    }

    int RsaWrappers::Decrypt(RSA* key, const unsigned char* msg, unsigned char*& result, unsigned int* result_len)
    {
        int status = SUCCESS;
        if (result_len != nullptr)
        {
            *result_len = 0;
        }

        // allocate the result pointer
        result = (unsigned char*)malloc(RSA_size(key));
        if (result == nullptr)
        {
            fprintf(stderr, "Encrypt: malloc failed to allocate result pointer of size %d\n", RSA_size(key));
            return GENERAL_FAILURE;
        }

        status = RsaWrappers::IsPrivateKey(key);
        if (status == 1)
        {
            // encrypt private
            status = RSA_private_decrypt(RSA_size(key), msg, result, key, RSA_PKCS1_PADDING);
            if (status < 0)
            {
                fprintf(stderr, "Decrypt: RSA_private_decrypt failed, returned status %d with error %s\n", status, ERR_error_string(ERR_get_error(), NULL));
                goto exit_failure;
            }
        }
        else if (status == 0)
        {
            // encrypt public
            status = RSA_public_decrypt(RSA_size(key), msg, result, key, RSA_PKCS1_PADDING);
            if (status < 0)
            {
                fprintf(stderr, "Decrypt: RSA_public_decrypt failed, returned status %d with error %s\n", status, ERR_error_string(ERR_get_error(), NULL));
                goto exit_failure;
            }
        }
        else
        {
            // error in IsPrivateKey, cleanup and get out
            goto exit_failure;
        }

        // update result_len from above
        if (result_len != nullptr)
        {
            *result_len = status;
        }

        return SUCCESS;

        exit_failure:
            free(result);
            return status;
    }
}
