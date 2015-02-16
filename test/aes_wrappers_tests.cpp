// Cameron Bielstein, 12/23/14
// rsa_wrappers_tests.cpp
// Holds unit tests for RsaWrappers class for UbiPAL

// Header
#include "aes_wrappers_tests.h"

// Tested code
#include "../src/aes_wrappers.h"

// Test helpers
#include "../src/error.h"
#include "test_helpers.h"

// Standard includes
#include <string.h>

namespace UbiPAL
{
    int AesWrappersTests::AesWrappersTestsCreateKeyIv()
    {
        int status = SUCCESS;
        unsigned char* key = nullptr;
        unsigned char* iv = nullptr;
        int key_len = 0;

        status = AesWrappers::GenerateAesObject(key, &key_len);
        if (status != SUCCESS)
        {
            goto exit;
        }
        if (key == nullptr || key_len == 0)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        status = AesWrappers::GenerateAesObject(iv, NULL);
        if (status != SUCCESS)
        {
            goto exit;
        }
        if (iv == nullptr)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            free(key);
            free(iv);
            return status;
    }

    int AesWrappersTests::AesWrappersTestsAesObjectsEqual()
    {
        int status = SUCCESS;
        unsigned char* obj1 = nullptr;
        unsigned char* obj2 = nullptr;

        // Both objects is null
        status = AesWrappers::AesObjectsEqual(NULL, NULL);
        if (status != 1)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        status = AesWrappers::GenerateAesObject(obj1, NULL);
        if (status != SUCCESS)
        {
            goto exit;
        }

        // One object is null
        status = AesWrappers::AesObjectsEqual(obj1, obj2);
        if (status != 0)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        // same pointers
        obj2 = obj1;
        status = AesWrappers::AesObjectsEqual(obj1, obj2);
        if (status != 1)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        // Same string, different pointers
        obj2 = (unsigned char*)malloc(AES_KEYLEN);
        if (obj2 == nullptr)
        {
            status = MALLOC_FAILURE;
            goto exit;
        }
        memcpy(obj2, obj1, AES_KEYLEN);
        status = AesWrappers::AesObjectsEqual(obj1, obj2);
        if (status != 1)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }
        free(obj2);

        // different pointers, different strings
        status = AesWrappers::GenerateAesObject(obj2, NULL);
        if (status != SUCCESS)
        {
            goto exit;
        }
        status = AesWrappers::AesObjectsEqual(obj1, obj2);
        if (status != 0)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            free(obj1);
            free(obj2);
            return status;
    }

    int AesWrappersTests::AesWrappersTestsAesObjectsStrings()
    {
        int status = SUCCESS;
        unsigned char* obj = nullptr;
        unsigned char* obj_result = nullptr;
        std::string obj_str;

        status = AesWrappers::GenerateAesObject(obj, nullptr);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = AesWrappers::ObjectToString(obj, obj_str);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = AesWrappers::StringToObject(obj_str, obj_result);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = AesWrappers::AesObjectsEqual(obj, obj_result);
        if (status != 1)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }
        else
        {
            status = SUCCESS;
            goto exit;
        }

        exit:
            free(obj);
            free(obj_result);
            return status;
    }

    int AesWrappersTests::AesWrappersTestsEncryptDecrypt()
    {
        int status = 0;
        const char* msg = "Live from New York, it's SATURDAY NIGHT!";
        unsigned char* msg_encrypted = nullptr;
        unsigned char* msg_decrypted = nullptr;
        unsigned char* key = nullptr;
        unsigned char* iv = nullptr;
        unsigned int encrypted_len = 0;
        unsigned int decrypted_len = 0;

        status = AesWrappers::GenerateAesObject(key, nullptr);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = AesWrappers::GenerateAesObject(iv, nullptr);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = AesWrappers::Encrypt(key, iv, (unsigned char*)msg, strlen(msg) + 1, msg_encrypted, &encrypted_len);
        if (status != SUCCESS)
        {
            goto exit;
        }

        if (memcmp(msg, msg_encrypted, strlen(msg) + 1) == 0)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        status = AesWrappers::Decrypt(key, iv, msg_encrypted, encrypted_len, msg_decrypted, &decrypted_len);
        if (status != SUCCESS)
        {
            goto exit;
        }

        if (decrypted_len != strlen(msg) + 1 || memcmp(msg, msg_decrypted, strlen(msg) + 1) != 0)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            free(msg_encrypted);
            free(key);
            free(iv);
            return status;
    }
    void AesWrappersTests::RunAesWrappersTests(unsigned int& module_count, unsigned int& module_fails)
    {
        TestHelpers::RunTestFunc(AesWrappersTestsCreateKeyIv, SUCCESS,
                                 "AesWrappersTestsCreateKeyIv", module_count, module_fails);
        TestHelpers::RunTestFunc(AesWrappersTestsAesObjectsEqual, SUCCESS,
                                 "AesWrappersTestsAesObjectsEqual", module_count, module_fails);
        TestHelpers::RunTestFunc(AesWrappersTestsAesObjectsStrings, SUCCESS,
                                 "AesWrappersTestsAesObjectsStrings", module_count, module_fails);
        TestHelpers::RunTestFunc(AesWrappersTestsEncryptDecrypt, SUCCESS,
                                 "AesWrappersTestsEncryptDecrypt", module_count, module_fails);
    }
}
