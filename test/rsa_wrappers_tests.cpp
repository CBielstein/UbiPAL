// Cameron Bielstein, 12/23/14
// rsa_wrappers_tests.cpp
// Holds unit tests for RsaWrappers class for UbiPAL

#include "rsa_wrappers_tests.h"
#include "../src/rsa_wrappers.h"
#include <string.h>
#include "../src/error.h"
#include "test_helpers.h"

namespace UbiPAL
{
    // signed by private, verified by public
    int RsaWrappersTests::RsaWrappersBasic()
    {
        int status = SUCCESS;
        unsigned char* sig;
        unsigned int sig_len;

        // create message
        const char* msg = "Hello, is it me you're looking for?";

        // get key pair
        RSA* priv;
        RSA* pub;
        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersBasic: Error in GenerateRsaKey: %d\n", status);
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, pub);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersBasic: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        // create message signature
        status = RsaWrappers::CreateSignedDigest(priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersBasic: Error in CreateSignedDigest: %d\n", status);
            goto exit;
        }

        // Test verification
        status = RsaWrappers::VerifySignedDigest(pub, (unsigned char*)msg, strlen(msg), sig, sig_len);
        if (status != 1)
        {
            fprintf(stderr, "RsaWrappersBasic: Failed to validate signature with status %d\n", status);
            status = GENERAL_FAILURE;
            goto exit;
        }
        status = SUCCESS;

        exit:
            RSA_free(priv);
            RSA_free(pub);
            free(sig);

        return status;
    }

    // signed by private, failed verification by wrong public key
    int RsaWrappersTests::RsaWrappersWrongPubKey()
    {
        int status = SUCCESS;
        unsigned char* sig;
        unsigned int sig_len;

        // create message
        const char* msg = "It Came Upon A Midnight Clear";

        // get key pair
        RSA* priv;
        RSA* pub;
        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersWrongPubKey: Error in GenerateRsaKey: %d\n", status);
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, pub);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersWrongPubKey: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        // create message signature
        status = RsaWrappers::CreateSignedDigest(priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersWrongPubKey: Error in CreateSignedDigest: %d\n", status);
            goto exit;
        }

        // get wrong keypair
        RSA* wrong_priv;
        RSA* wrong_pub;
        status = RsaWrappers::GenerateRsaKey(wrong_priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersWrongPubKey: Error in GenerateRsaKey: %d\n", status);
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(wrong_priv, wrong_pub);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersWrongPubKey: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        // Test verification
        status = RsaWrappers::VerifySignedDigest(wrong_pub, (unsigned char*)msg, strlen(msg), sig, sig_len);
        if (status == 1)
        {
            fprintf(stderr, "RsaWrappersWrongPubKey: Incorrectly validated signature with different public key\n");
            status = GENERAL_FAILURE;
            goto exit;
        }
        status = SUCCESS;

        exit:
            RSA_free(priv);
            RSA_free(pub);
            RSA_free(wrong_priv);
            RSA_free(wrong_pub);
            free(sig);

        return status;
    }

    // signed by private, failed verification by wrong private key
    int RsaWrappersTests::RsaWrappersWrongPrivKey()
    {
        int status = SUCCESS;
        unsigned char* sig;
        unsigned int sig_len;

        // create message
        const char* msg = "Sleighbells in the air, beauty everywhere. Yule tide by the fireside and joyful memories there. Christmas time is here.";

        // get key pair
        RSA* priv;
        RSA* pub;
        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersWrongPrivKey: Error in GenerateRsaKey: %d\n", status);
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, pub);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersWrongPrivKey: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        // create message signature
        status = RsaWrappers::CreateSignedDigest(priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersWrongPrivKey: Error in CreateSignedDigest: %d\n", status);
            goto exit;
        }

        // get wrong keypair
        RSA* wrong_priv;
        RSA* wrong_pub;
        status = RsaWrappers::GenerateRsaKey(wrong_priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersWrongPrivKey: Error in GenerateRsaKey: %d\n", status);
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(wrong_priv, wrong_pub);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersWrongPrivKey: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        // Test verification
        status = RsaWrappers::VerifySignedDigest(wrong_priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
        if (status == 1)
        {
            fprintf(stderr, "RsaWrappersWrongPrivKey: Incorrectly validated signature with different public key\n");
            status = GENERAL_FAILURE;
            goto exit;
        }
        status = SUCCESS;

        exit:
            RSA_free(priv);
            RSA_free(pub);
            RSA_free(wrong_priv);
            RSA_free(wrong_pub);
            free(sig);

        return status;
    }

    int RsaWrappersTests::RsaWrappersIsPrivateTrue()
    {
        int status = SUCCESS;

        RSA* priv;
        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersIsPrivateTrue: Failed to generate a public key.\n");
            goto exit;
        }

        status = RsaWrappers::IsPrivateKey(priv);
        if (status != 1)
        {
            fprintf(stderr, "RsaWrappersIsPrivateTrue: IsPrivateKey failed to identify private key. Returned %d\n", status);
            goto exit;
        }
        else
        {
            status = SUCCESS;
        }

        exit:
            RSA_free(priv);
            return status;
    }

    int RsaWrappersTests::RsaWrappersIsPrivateFalse()
    {
        int status = SUCCESS;

        RSA* priv;
        RSA* pub;
        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersIsPrivateTrue: Failed to generate a public key.\n");
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, pub);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersBasic: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        status = RsaWrappers::IsPrivateKey(pub);
        if (status != 0)
        {
            fprintf(stderr, "RsaWrappersIsPrivateTrue: IsPrivateKey wrongly identified private key. Returned %d\n", status);
            goto exit;
        }
        else
        {
            status = SUCCESS;
        }

        exit:
            RSA_free(priv);
            RSA_free(pub);
            return status;
    }

    // Encrypt public, Decrypt private
    int RsaWrappersTests::RsaWrappersEncryptDecryptBasic()
    {
        int status = SUCCESS;

        // create message
        const char* msg = "Buddy the Elf, what's your favorite color?";

        // create keypair
        RSA* priv;
        RSA* pub;
        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptBasic: Failed to generate a public key.\n");
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, pub);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptBasic: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        // Encrypt
        unsigned char* result;
        unsigned int bytes_Encrypted;
        status = RsaWrappers::Encrypt(pub, (unsigned char*)msg, strlen(msg), result, &bytes_Encrypted);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptBasic: Error in Encrypt: %d, %d bytes Encrypted\n", status, bytes_Encrypted);
            goto exit;
        }

        // Decrypt
        unsigned char* result_msg;
        unsigned int bytes_Decrypted;
        status = RsaWrappers::Decrypt(priv, result, result_msg, &bytes_Decrypted);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptBasic: Error in Decrypt: %d, %d bytes Decrypted\n", status, bytes_Decrypted);
            goto exit;
        }

        // compare
        status = memcmp(msg, result_msg, bytes_Decrypted);
        if (status != 0 || strlen(msg) != bytes_Decrypted)
        {
            fprintf(stderr, "rsa_wrappers_encryp_Decrypt_basic: Strings don't match: %s, %s or lengths don't match: %lu, %d\n",
                    msg, result_msg, strlen(msg), bytes_Decrypted);
            status = GENERAL_FAILURE;
            goto exit;
        }
        else
        {
            status = SUCCESS;
            goto exit;
        }

        exit:
            RSA_free(priv);
            RSA_free(pub);
            free(result);
            free(result_msg);
            return status;
    }

    // Encrypt private, Decrypt public
    int RsaWrappersTests::RsaWrappersEncryptDecryptBasicReverse()
    {
        int status = SUCCESS;

        // create message
        const char* msg = "Peter Piper picked a peck of pickled peppers.";

        // create keypair
        RSA* priv;
        RSA* pub;
        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptBasicReverse: Failed to generate a public key.\n");
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, pub);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptBasicReverse: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        // Encrypt
        unsigned char* result;
        unsigned int bytes_Encrypted;
        status = RsaWrappers::Encrypt(priv, (unsigned char*)msg, strlen(msg), result, &bytes_Encrypted);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptBasicReverse: Error in Encrypt: %d, %d bytes Encrypted\n", status, bytes_Encrypted);
            goto exit;
        }

        // Decrypt
        unsigned char* result_msg;
        unsigned int bytes_Decrypted;
        status = RsaWrappers::Decrypt(pub, result, result_msg, &bytes_Decrypted);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptBasicReverse: Error in Decrypt: %d, %d bytes Decrypted\n", status, bytes_Decrypted);
            goto exit;
        }

        // compare
        status = memcmp(msg, result_msg, bytes_Decrypted);
        if (status != 0 || strlen(msg) != bytes_Decrypted)
        {
            fprintf(stderr, "rsa_wrappers_encryp_Decrypt_basic_reverse: Strings don't match: %s, %s, or lengths don't match: %lu/%d\n",
                    msg, result_msg, strlen(msg), bytes_Decrypted);
            status = GENERAL_FAILURE;
            goto exit;
        }
        else
        {
            status = SUCCESS;
            goto exit;
        }

        exit:
            RSA_free(priv);
            RSA_free(pub);
            free(result);
            free(result_msg);
            return status;
    }

    // Encrypt public, Decrypt wrong private and fail
    int RsaWrappersTests::RsaWrappersEncryptDecryptWrongKey()
    {
        int status = SUCCESS;

        // create message
        const char* msg = "Peter Piper picked a peck of pickled peppers.";

        // create keypair
        RSA* priv;
        RSA* pub;
        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptWrongKey: Failed to generate a public key.\n");
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, pub);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptWrongKey: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        // create second key
        RSA* priv_wrong;
        status = RsaWrappers::GenerateRsaKey(priv_wrong);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptWrongKey: Failed to generate a public key.\n");
            goto exit;
        }

        // Encrypt
        unsigned char* result;
        unsigned int bytes_Encrypted;
        status = RsaWrappers::Encrypt(pub, (unsigned char*)msg, strlen(msg), result, &bytes_Encrypted);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptWrongKey: Error in Encrypt: %d, %d bytes Encrypted\n", status, bytes_Encrypted);
            goto exit;
        }

        // Decrypt with wrong key
        unsigned char* result_msg;
        unsigned int bytes_Decrypted;
        status = RsaWrappers::Decrypt(priv_wrong, result, result_msg, &bytes_Decrypted);
        if (status == SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptWrongKey: Decrypt wrongly succeeded: %d, %d bytes Decrypted\n", status, bytes_Decrypted);
            goto exit;
        }

        status = SUCCESS;

        exit:
            RSA_free(priv);
            RSA_free(pub);
            RSA_free(priv_wrong);
            free(result);
            return status;
    }

    // Encrypt private, Decrypt wrong public and fail
    int RsaWrappersTests::RsaWrappersEncryptDecryptWrongKeyReverse()
    {
        int status = SUCCESS;

        // create message
        const char* msg = "Everything is bigger in Texas!";

        // create key
        RSA* priv;
        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptWrongKeyReverse: Failed to generate a public key.\n");
            goto exit;
        }

        // create wrong keypair
        RSA* priv_wrong;
        RSA* pub_wrong;
        status = RsaWrappers::GenerateRsaKey(priv_wrong);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptWrongKeyReverse: Failed to generate a public key.\n");
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv_wrong, pub_wrong);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptWrongKeyReverse: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        // Encrypt
        unsigned char* result;
        unsigned int bytes_Encrypted;
        status = RsaWrappers::Encrypt(priv, (unsigned char*)msg, strlen(msg), result, &bytes_Encrypted);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptWrongKeyReverse: Error in Encrypt: %d, %d bytes Encrypted\n", status, bytes_Encrypted);
            goto exit;
        }

        // Decrypt with wrong key
        unsigned char* result_msg;
        unsigned int bytes_Decrypted;
        status = RsaWrappers::Decrypt(pub_wrong, result, result_msg, &bytes_Decrypted);
        if (status == SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptWrongKeyReverse: Decrypt wrongly succeeded: %d, %d bytes Decrypted\n", status, bytes_Decrypted);
            goto exit;
        }

        status = SUCCESS;

        exit:
            RSA_free(priv);
            RSA_free(priv_wrong);
            RSA_free(pub_wrong);
            free(result);
            return status;
    }

    // Encrypt private, Decrypt public
    int RsaWrappersTests::RsaWrappersEncryptDecryptPublicFail()
    {
        int status = SUCCESS;

        // create message
        const char* msg = "Peter Piper picked a peck of pickled peppers.";

        // create keypair
        RSA* priv;
        RSA* pub;
        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptPublicFail: Failed to generate a public key.\n");
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, pub);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptPublicFail: Error in CreatePublicKey: %d\n", status);
            goto exit;
        }

        // Encrypt
        unsigned char* result;
        unsigned int bytes_Encrypted;
        status = RsaWrappers::Encrypt(pub, (unsigned char*)msg, strlen(msg), result, &bytes_Encrypted);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptPublicFail: Error in Encrypt: %d, %d bytes Encrypted\n", status, bytes_Encrypted);
            goto exit;
        }

        // Decrypt
        unsigned char* result_msg;
        unsigned int bytes_Decrypted;
        status = RsaWrappers::Decrypt(pub, result, result_msg, &bytes_Decrypted);
        if (status == SUCCESS)
        {
            fprintf(stderr, "RsaWrappersEncryptDecryptPublicFail: Incorrectly succeeded in Decrypt: %d, %d bytes Decrypted\n", status, bytes_Decrypted);
            goto exit;
        }

        status = SUCCESS;

        exit:
            RSA_free(priv);
            RSA_free(pub);
            free(result);
            return status;
    }

    void RsaWrappersTests::RunRsaWrappersTests(unsigned int& module_count, unsigned int& module_fails)
    {
        TestHelpers::RunTestFunc(RsaWrappersBasic, SUCCESS,
                                 "RsaWrappersBasic", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersWrongPubKey, SUCCESS,
                                 "RsaWrappersWrongPubKey", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersWrongPrivKey, SUCCESS,
                                 "RsaWrappersWrongPrivKey", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersIsPrivateTrue, SUCCESS,
                                 "RsaWrappersIsPrivateTrue", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersIsPrivateFalse, SUCCESS,
                                 "RsaWrappersIsPrivateFalse", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersEncryptDecryptBasic, SUCCESS,
                                 "RsaWrappersEncryptDecryptBasic", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersEncryptDecryptBasicReverse, SUCCESS,
                                 "RsaWrappersEncryptDecryptBasicReverse", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersEncryptDecryptWrongKey, SUCCESS,
                                 "RsaWrappersEncryptDecryptWrongKey", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersEncryptDecryptWrongKeyReverse, SUCCESS,
                                 "RsaWrappersEncryptDecryptWrongKeyReverse", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersEncryptDecryptPublicFail, SUCCESS,
                                 "RsaWrappersEncryptDecryptPublicFail", module_count, module_fails);
    }
}
