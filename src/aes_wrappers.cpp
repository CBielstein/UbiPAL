// Cameron Bielstein, 2/14/15
// aes_wrappers.cpp
// Wrapper functions for OpenSSL's symmetric encryption and decryption algorithms

// Header
#include "aes_wrappers.h"

// UbiPAL includes
#include "error.h"
#include "log.h"
#include "macros.h"

// OpenSSL includes
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

// Standard includes
#include <string.h>

namespace UbiPAL
{
    int AesWrappers::GenerateAesObject(unsigned char*& obj, int* obj_len)
    {
        FUNCTION_START;
        const unsigned int length = AES_KEYLEN/8;
        if (obj_len != nullptr)
        {
            *obj_len = length;
        }

        obj = (unsigned char*)malloc(length);
        if (obj == nullptr)
        {
            RETURN_STATUS(MALLOC_FAILURE);
        }

        returned_value = RAND_bytes(obj, length);
        if (returned_value != 1)
        {
            Log::Line(Log::EMERG, "AesWrappers::GenerateAesKey: RAND_bytes failed: %d, %s", returned_value, ERR_error_string(ERR_get_error(), NULL));
            RETURN_STATUS(GENERAL_FAILURE);
        }

        exit:
            if (status != SUCCESS)
            {
                free(obj);
            }
            FUNCTION_END;
    }

    int AesWrappers::AesObjectsEqual(const unsigned char* const a, const unsigned char* const b)
    {
        if (!((a == nullptr) ^ (b == nullptr)) && (a == b || memcmp(a, b, AES_KEYLEN) == 0))
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }

    int AesWrappers::ObjectToString(const unsigned char* const obj, std::string& str)
    {
        if (obj == nullptr)
        {
            return NULL_ARG;
        }

        str = std::string((const char* const)obj, AES_KEYLEN);
        return SUCCESS;
    }

    int AesWrappers::StringToObject(const std::string& str, unsigned char*& key)
    {
        key = (unsigned char*) malloc(str.size());
        if (key == nullptr)
        {
            return MALLOC_FAILURE;
        }

        memcpy(key, str.c_str(), str.size());
        return SUCCESS;
    }

    int AesWrappers::Encrypt(const unsigned char* const key, const unsigned char* const iv,
                             const unsigned char* const msg, const unsigned int& msg_len, unsigned char*& result, unsigned int* result_len)
    {
        FUNCTION_START;
        EVP_CIPHER_CTX ctx;
        unsigned int res_len = 0;
        unsigned int length = 0;
        int temp_len = 0;
        const EVP_CIPHER* cipher = EVP_aes_256_cbc();

        if (key == nullptr || iv == nullptr || msg == nullptr)
        {
            RETURN_STATUS(NULL_ARG);
        }

        if (result_len != nullptr)
        {
            *result_len = 0;
        }

        // allocate space for result
        res_len = msg_len + EVP_CIPHER_block_size(cipher);
        result = (unsigned char*)malloc(res_len);
        if (result == nullptr)
        {
            RETURN_STATUS(MALLOC_FAILURE);
        }

        // Init cipher and encrption
        EVP_CIPHER_CTX_init(&ctx);
        returned_value = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);
        if (returned_value != 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        returned_value = EVP_EncryptUpdate(&ctx, result, &temp_len, msg, msg_len);
        if (returned_value != 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }
        length += temp_len;

        returned_value = EVP_EncryptFinal_ex(&ctx, result + length, &temp_len);
        if (returned_value != 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }
        length += temp_len;

        if (result_len != nullptr)
        {
            *result_len = length;
        }

        exit:
            EVP_CIPHER_CTX_cleanup(&ctx);
            if (status != SUCCESS)
            {
                free(result);
            }
            FUNCTION_END;
    }

    int AesWrappers::Decrypt(const unsigned char* const key, const unsigned  char* const iv,
                             const unsigned char* const msg, const unsigned int& msg_len, unsigned char*& result, unsigned int* result_len)
    {
        FUNCTION_START;
        EVP_CIPHER_CTX ctx;
        unsigned int res_len = 0;
        unsigned int length = 0;
        int temp_len = 0;
        const EVP_CIPHER* cipher = EVP_aes_256_cbc();

        if (key == nullptr || iv == nullptr || msg == nullptr)
        {
            RETURN_STATUS(NULL_ARG);
        }

        if (result_len != nullptr)
        {
            *result_len = 0;
        }

        // allocate space for result
        res_len = msg_len + EVP_CIPHER_block_size(cipher);
        result = (unsigned char*)malloc(res_len);
        if (result == nullptr)
        {
            RETURN_STATUS(MALLOC_FAILURE);
        }

        // Init cipher and encrption
        EVP_CIPHER_CTX_init(&ctx);
        returned_value = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);
        if (returned_value != 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        returned_value = EVP_DecryptUpdate(&ctx, result, &temp_len, msg, msg_len);
        if (returned_value != 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }
        length += temp_len;

        returned_value = EVP_DecryptFinal_ex(&ctx, result + length, &temp_len);
        if (returned_value != 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }
        length += temp_len;

        if (result_len != nullptr)
        {
            *result_len = length;
        }

        exit:
            EVP_CIPHER_CTX_cleanup(&ctx);
            if (status != SUCCESS)
            {
                free(result);
            }
            FUNCTION_END;
    }
}
