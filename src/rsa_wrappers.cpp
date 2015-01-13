// Cameron Bielstein, 12/23/14
// rsa_wrappers.cpp
// Wrapper functions for OpenSSL's RSA encryption and verification algorithms

// Header
#include "rsa_wrappers.h"

// UbiPAL includes
#include "macros.h"
#include "log.h"

// Standard includes
#include <stdlib.h>
#include <time.h>

// OpenSSL includes
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bn.h>


namespace UbiPAL
{
    int RsaWrappers::GenerateRsaKey(RSA*& rsa)
    {
        FUNCTION_START;

        // we're creating a NEW key at rsa
        rsa = RSA_new();

        // set e = 3. This is not proven to be less secure than larger numbers with PKCS padding used by OpenSSL
        // and this gives speed increases important for low-end devices
        BIGNUM* e = BN_new();
        if (e == nullptr)
        {
            Log::Line(Log::EMERG, "RsaWrappers::GenerateRsaKey: Failed on BN_new(), returned NULL");
            RETURN_STATUS(OPENSSL_ERROR);
        }

        returned_value = BN_set_bit(e, 0);
        if (returned_value != 1)
        {
            Log::Line(Log::EMERG, "RsaWrappers::GenerateRsaKey: Failed on BN_set_bit(e,0), returned: %d, error: %s", returned_value, ERR_error_string(ERR_get_error(), NULL));
            RETURN_STATUS(OPENSSL_ERROR);
        }

        returned_value = BN_set_bit(e, 1);
        if (returned_value != 1)
        {
            Log::Line(Log::EMERG, "RsaWrappers::GenerateRsaKey: Failed on BN_set_bit(e,1), returned: %d, error: %s", returned_value, ERR_error_string(ERR_get_error(), NULL));
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // seed time
        srand(time(NULL));

        // generate key
        returned_value = RSA_generate_key_ex(rsa, 1024, e, NULL);
        if (returned_value < 0)
        {
            Log::Line(Log::EMERG, "RsaWrappers::GenerateRsaKey: Failed onRSA_generate_key_ex(), returned: %d, error: %s", returned_value, ERR_error_string(ERR_get_error(), NULL));
            RETURN_STATUS(OPENSSL_ERROR);
        }

        exit:
            if (status != SUCCESS)
            {
                RSA_free(rsa);
            }
            BN_free(e);
            FUNCTION_END;
    }

    int RsaWrappers::CreatePublicKey(const RSA* priv_key, RSA*& pub_key)
    {
        FUNCTION_START;

        if (priv_key == nullptr)
        {
            Log::Line(Log::WARN, "RsaWrappers::CreatePublicKey: Passed a null argument in CreatePublicKey(%p, %p)", priv_key, pub_key);
            RETURN_STATUS(NULL_ARG);
        }

        // we're creating a NEW key at pub_key
        pub_key = RSA_new();

        // copy over public elements
        pub_key->n = BN_dup(priv_key->n);
        pub_key->e = BN_dup(priv_key->e);

        exit:
            FUNCTION_END;
    }

    int RsaWrappers::CreateSignedDigest(RSA* priv_key, const unsigned char* msg,
                                        const unsigned int msg_length, unsigned char*& sig,
                                        unsigned int& sig_len)
    {
        FUNCTION_START;
        unsigned char* digest = nullptr;

        if (priv_key == nullptr || msg == nullptr)
        {
            Log::Line(Log::WARN, "RsaWrappers::CreateSignedDigest: Passed a null argument in  CreateSignedDigest(%p, %p, %u, %p, %d)", priv_key, msg, msg_length, sig, sig_len);
            RETURN_STATUS(NULL_ARG);
        }

        // hash the message
        digest = SHA1(msg, msg_length, NULL);
        if (digest == nullptr)
        {
            Log::Line(Log::EMERG, "RsaWrappers::CreateSignedDigest: SHA1 failed, returned NULL");
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // sign that digest!
        sig = (unsigned char*)malloc(RSA_size(priv_key));
        if (sig == nullptr)
        {
            Log::Line(Log::EMERG, "RsaWrappers::CreateSignedDigest: malloc failed to allocate %lu bytes for signature, returned NULL", RSA_size(priv_key));
            RETURN_STATUS(MALLOC_FAILURE);
        }

        returned_value = RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sig, &sig_len, priv_key);
        if (returned_value != 1)
        {
            Log::Line(Log::EMERG, "RsaWrappers::CreateSignedDigest: RSA_sign failed, returned: %d, error: %s", status, ERR_error_string(ERR_get_error(), NULL));
            RETURN_STATUS(OPENSSL_ERROR);
        }

        exit:
            FUNCTION_END;
    }

    int RsaWrappers::VerifySignedDigest(RSA* pub_key, const unsigned char* msg,
                                        const unsigned int msg_length, const unsigned char* sig,
                                        const unsigned int sig_len)
    {
        FUNCTION_START;
        unsigned char* digest = nullptr;

        digest = SHA1(msg, msg_length, NULL);
        if (digest == nullptr)
        {
            Log::Line(Log::EMERG, "RsaWrappers::VerifySignedDigest: SHA1 failed, returned NULL");
            RETURN_STATUS(OPENSSL_ERROR);
        }

        returned_value = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, (unsigned char *)sig, sig_len, pub_key);
        if (returned_value == 1)
        {
            RETURN_STATUS(1);
        }
        else if (returned_value == 0)
        {
            RETURN_STATUS(0);
        }
        else
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        exit:
            FUNCTION_END;
    }

    int RsaWrappers::IsPrivateKey(const RSA* key)
    {
        if (key == nullptr)
        {
            Log::Line(Log::WARN, "RsaWrappers::IsPrivateKey: passed null argument");
            return NULL_ARG;
        }
        return (key->d == nullptr) ? 0 : 1;
    }

    int RsaWrappers::Encrypt(RSA* key, const unsigned char* msg, const unsigned int& msg_len, unsigned char*& result, unsigned int* result_len)
    {
        FUNCTION_START;

        if (result_len != nullptr)
        {
            *result_len = 0;
        }

        // msg needs to be no longer than max message length
        if (msg_len > RsaWrappers::MaxMessageLength(key))
        {
            Log::Line(Log::WARN, "RsaWrappers::Encrypt: Message was too long. Length: %d, max length: %d", msg_len, RsaWrappers::MaxMessageLength(key));
            RETURN_STATUS(MESSAGE_TOO_LONG);
        }

        // allocate the result pointer
        result = (unsigned char*)malloc(RSA_size(key));
        if (result == nullptr)
        {
            Log::Line(Log::EMERG, "RsaWrappers::Encrypt: malloc failed to allocate result pointer of size %d", RSA_size(key));
            RETURN_STATUS(MALLOC_FAILURE);
        }

        // seed random number generator
        srand(time(NULL));

        returned_value = RsaWrappers::IsPrivateKey(key);
        if (returned_value == 1)
        {
            // encrypt private
            returned_value = RSA_private_encrypt(msg_len, msg, result, key, RSA_PKCS1_PADDING);
            if (returned_value < 0)
            {
                Log::Line(Log::EMERG, "RsaWrappers::Encrypt: RSA_private_encrypt failed, returned status %d with error %s", returned_value, ERR_error_string(ERR_get_error(), NULL));
                RETURN_STATUS(OPENSSL_ERROR);
            }
        }
        else if (returned_value == 0)
        {
            // encrypt public
            returned_value = RSA_public_encrypt(msg_len, msg, result, key, RSA_PKCS1_PADDING);
            if (returned_value < 0)
            {
                Log::Line(Log::EMERG, "RsaWrappers::Encrypt: RSA_public_encrypt failed, returned status %d with error %s", returned_value, ERR_error_string(ERR_get_error(), NULL));
                RETURN_STATUS(OPENSSL_ERROR);
            }
        }
        else
        {
            // error in IsPrivateKey, cleanup and get out
            Log::Line(Log::EMERG, "RsaWrappers::Encrypt: RsaWrappers::IsPrivateKey failed to return 1 or 0, returned: %d, %s", status, GetErrorDescription(status));
            RETURN_STATUS(returned_value);
        }

        // update result_len from above
        if (result_len != nullptr)
        {
            *result_len = returned_value;
        }

        exit:
            if (status != SUCCESS)
            {
                free(result);
            }
            FUNCTION_END;
    }

    int RsaWrappers::Decrypt(RSA* key, const unsigned char* msg, unsigned char*& result, unsigned int* result_len)
    {
        FUNCTION_START;

        if (result_len != nullptr)
        {
            *result_len = 0;
        }

        // allocate the result pointer
        result = (unsigned char*)malloc(RSA_size(key));
        if (result == nullptr)
        {
            Log::Line(Log::EMERG, "RsaWrappers::Decrypt: malloc failed to allocate result pointer of size %d", RSA_size(key));
            RETURN_STATUS(MALLOC_FAILURE);
        }

        returned_value = RsaWrappers::IsPrivateKey(key);
        if (returned_value == 1)
        {
            // encrypt private
            returned_value = RSA_private_decrypt(RSA_size(key), msg, result, key, RSA_PKCS1_PADDING);
            if (returned_value < 0)
            {
                Log::Line(Log::EMERG, "RsaWrappers::Decrypt: RSA_private_decrypt failed, returned status %d with error %s", returned_value, ERR_error_string(ERR_get_error(), NULL));
                RETURN_STATUS(OPENSSL_ERROR);
            }
        }
        else if (returned_value == 0)
        {
            // encrypt public
            returned_value = RSA_public_decrypt(RSA_size(key), msg, result, key, RSA_PKCS1_PADDING);
            if (returned_value < 0)
            {
                Log::Line(Log::EMERG, "RsaWrappers::Decrypt: RSA_public_decrypt failed, returned status %d with error %s", returned_value, ERR_error_string(ERR_get_error(), NULL));
                RETURN_STATUS(OPENSSL_ERROR);
            }
        }
        else
        {
            // error in IsPrivateKey, cleanup and get out
            Log::Line(Log::EMERG, "RsaWrappers::Encrypt: RsaWrappers::IsPrivateKey failed to return 1 or 0, returned: %d, %s", status, GetErrorDescription(status));
            RETURN_STATUS(returned_value);
        }

        // update result_len from above
        if (result_len != nullptr)
        {
            *result_len = returned_value;
        }

        exit:
            if (status != SUCCESS)
            {
                free(result);
            }
            FUNCTION_END;
    }
}
