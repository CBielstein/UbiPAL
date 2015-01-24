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

    int RsaWrappersTests::RsaWrappersCopyKeyPrivate()
    {
        int status = SUCCESS;
        RSA* from = nullptr;
        RSA* to = nullptr;

        status = RsaWrappers::GenerateRsaKey(from);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersTests::RsaWrappersCopyKeyPrivate: GenerateRsaKey failed: %s\n", GetErrorDescription(status));
            goto exit;
        }

        status = RsaWrappers::CopyKey(from, to);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersTests::RsaWrappersCopyKeyPrivate: CopyKey failed: %s\n", GetErrorDescription(status));
            goto exit;
        }

        if (BN_cmp(from->n, to->n) != 0 ||
            BN_cmp(from->e, to->e) != 0 ||
            BN_cmp(from->d, to->d) != 0 ||
            BN_cmp(from->p, to->p) != 0 ||
            BN_cmp(from->q, to->q) != 0 ||
            BN_cmp(from->dmp1, to->dmp1) != 0 ||
            BN_cmp(from->dmq1, to->dmq1) != 0 ||
            BN_cmp(from->iqmp, to->iqmp) != 0)
        {
            fprintf(stderr, "RsaWrappersTests::RsaWrappersCopyKeyPrivate: Key mismatch\n");
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            RSA_free(from);
            RSA_free(to);
            return status;
    }

    int RsaWrappersTests::RsaWrappersCopyKeyPublic()
    {
        int status = SUCCESS;
        RSA* priv = nullptr;
        RSA* from = nullptr;
        RSA* to = nullptr;

        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersTests::RsaWrappersCopyKeyPublic: GenerateRsaKey failed: %s\n", GetErrorDescription(status));
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, from);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersTests::RsaWrappersCopyKeyPublic: CreatePublicKey failed: %s\n", GetErrorDescription(status));
            goto exit;
        }

        status = RsaWrappers::CopyKey(from, to);
        if (status != SUCCESS)
        {
            fprintf(stderr, "RsaWrappersTests::RsaWrappersCopyKeyPublic: CopyKey failed: %s\n", GetErrorDescription(status));
            goto exit;
        }

        if (BN_cmp(from->n, to->n) != 0 ||
            BN_cmp(from->e, to->e) != 0 ||
            BN_cmp(from->d, to->d) != 0 ||
            BN_cmp(from->p, to->p) != 0 ||
            BN_cmp(from->q, to->q) != 0 ||
            BN_cmp(from->dmp1, to->dmp1) != 0 ||
            BN_cmp(from->dmq1, to->dmq1) != 0 ||
            BN_cmp(from->iqmp, to->iqmp) != 0)
        {
            fprintf(stderr, "RsaWrappersTests::RsaWrappersCopyKeyPublic: Key mismatch\n");
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            RSA_free(priv);
            RSA_free(from);
            RSA_free(to);
            return status;
    }

    int RsaWrappersTests::RsaWrappersKeysEqualTrueSameKey()
    {
        int status = SUCCESS;
        RSA* a = nullptr;
        RSA* b = nullptr;
        int ret_val = 0;

        status = RsaWrappers::GenerateRsaKey(a);
        if (status != SUCCESS)
        {
            goto exit;
        }

        b = a;

        ret_val = RsaWrappers::KeysEqual(a, b);
        if (ret_val != 1)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            RSA_free(a);
            return status;
    }

    int RsaWrappersTests::RsaWrappersKeysEqualTruePrivate()
    {
        int status = SUCCESS;
        RSA* a = nullptr;
        RSA* b = nullptr;
        int ret_val = 0;

        status = RsaWrappers::GenerateRsaKey(a);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = RsaWrappers::CopyKey(a, b);
        if (status != SUCCESS)
        {
            goto exit;
        }

        ret_val = RsaWrappers::KeysEqual(a, b);
        if (ret_val != 1)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            RSA_free(a);
            RSA_free(b);
            return status;
    }

    int RsaWrappersTests::RsaWrappersKeysEqualFalsePrivate()
    {
        int status = SUCCESS;
        RSA* a = nullptr;
        RSA* b = nullptr;
        int ret_val = 0;

        status = RsaWrappers::GenerateRsaKey(a);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = RsaWrappers::GenerateRsaKey(b);
        if (status != SUCCESS)
        {
            goto exit;
        }

        ret_val = RsaWrappers::KeysEqual(a, b);
        if (ret_val != 0)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            RSA_free(a);
            RSA_free(b);
            return status;
    }

    int RsaWrappersTests::RsaWrappersKeysEqualTruePublic()
    {
        int status = SUCCESS;
        RSA* priv = nullptr;
        RSA* a = nullptr;
        RSA* b = nullptr;
        int ret_val = 0;

        status = RsaWrappers::GenerateRsaKey(priv);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, a);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv, b);
        if (status != SUCCESS)
        {
            goto exit;
        }

        ret_val = RsaWrappers::KeysEqual(a, b);
        if (ret_val != 1)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            RSA_free(a);
            RSA_free(b);
            RSA_free(priv);
            return status;
    }

    int RsaWrappersTests::RsaWrappersKeysEqualFalsePublic()
    {
        int status = SUCCESS;
        RSA* priv_a = nullptr;
        RSA* priv_b = nullptr;
        RSA* a = nullptr;
        RSA* b = nullptr;
        int ret_val = 0;

        status = RsaWrappers::GenerateRsaKey(priv_a);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv_a, a);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = RsaWrappers::GenerateRsaKey(priv_b);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(priv_b, b);
        if (status != SUCCESS)
        {
            goto exit;
        }

        ret_val = RsaWrappers::KeysEqual(a, b);
        if (ret_val != 0)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            RSA_free(priv_a);
            RSA_free(priv_b);
            RSA_free(a);
            RSA_free(b);
            return status;
    }

    int RsaWrappersTests::RsaWrappersKeysEqualFalsePublicPrivate()
    {
        int status = SUCCESS;
        RSA* a = nullptr;
        RSA* b = nullptr;
        int ret_val = 0;

        status = RsaWrappers::GenerateRsaKey(a);
        if (status != SUCCESS)
        {
            goto exit;
        }

        status = RsaWrappers::CreatePublicKey(a, b);
        if (status != SUCCESS)
        {
            goto exit;
        }

        ret_val = RsaWrappers::KeysEqual(a, b);
        if (ret_val != 0)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            RSA_free(a);
            RSA_free(b);
            return status;
    }

    int RsaWrappersTests::RsaWrappersGenerateKey()
    {
        int status = SUCCESS;
        int ret_val = 0;
        RSA* key = nullptr;

        status = RsaWrappers::GenerateRsaKey(key);
        if (status != SUCCESS)
        {
            goto exit;
        }

        ret_val = RSA_check_key(key);
        if (ret_val != 1)
        {
            status = GENERAL_FAILURE;
            goto exit;
        }

        exit:
            RSA_free(key);
            return status;
    }

    void RsaWrappersTests::RunRsaWrappersTests(unsigned int& module_count, unsigned int& module_fails)
    {
        TestHelpers::RunTestFunc(RsaWrappersGenerateKey, SUCCESS,
                                 "RsaWrappersGenerateKey", module_count, module_fails);
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
        TestHelpers::RunTestFunc(RsaWrappersCopyKeyPrivate, SUCCESS,
                                 "RsaWrappersCopyKeyPrivate", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersCopyKeyPublic, SUCCESS,
                                 "RsaWrappersCopyKeyPublic", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersKeysEqualTrueSameKey, SUCCESS,
                                 "RsaWrappersKeysEqualTrueSameKey", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersKeysEqualTruePrivate, SUCCESS,
                                 "RsaWrappersKeysEqualTruePrivate", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersKeysEqualFalsePrivate, SUCCESS,
                                 "RsaWrappersKeysEqualFalsePrivate", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersKeysEqualTruePublic, SUCCESS,
                                 "RsaWrappersKeysEqualTruePublic", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersKeysEqualFalsePublic, SUCCESS,
                                 "RsaWrappersKeysEqualFalsePublic", module_count, module_fails);
        TestHelpers::RunTestFunc(RsaWrappersKeysEqualFalsePublicPrivate, SUCCESS,
                                 "RsaWrappersKeysEqualFalsePublicPrivate", module_count, module_fails);
    }
}
