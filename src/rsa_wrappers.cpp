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

// variables for evaluation
#ifdef EVALUATE
    uint32_t NUM_RSA_ENCRYPTS = 0;
    double TIME_RSA_ENCRYPTS = 0;
    uint32_t NUM_RSA_DECRYPTS = 0;
    double TIME_RSA_DECRYPTS = 0;
    uint32_t NUM_RSA_SIGNS = 0;
    double TIME_RSA_SIGNS = 0;
    uint32_t NUM_RSA_VERIFIES = 0;
    double TIME_RSA_VERIFIES = 0;
    uint32_t NUM_RSA_GENERATES = 0;
    double TIME_RSA_GENERATES = 0;
#endif

namespace UbiPAL
{
    int RsaWrappers::GenerateRsaKey(RSA*& rsa)
    {
        FUNCTION_START;

        #ifdef EVALUATE
            clock_t start = clock();
        #endif

        BIGNUM* e = nullptr;

        // we're creating a NEW key at rsa
        rsa = RSA_new();
        if (rsa == nullptr)
        {
            Log::Line(Log::EMERG, "RsaWrappers::GenerateRsaKey: RSA_new failed: %s", ERR_error_string(ERR_get_error(), NULL));
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // set e = 3. This is not proven to be less secure than larger numbers with PKCS padding used by OpenSSL
        // and this gives speed increases important for low-end devices
        e = BN_new();
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
            #ifdef EVALUATE
                if (status == SUCCESS)
                {
                    clock_t end = clock();
                    TIME_RSA_GENERATES += ((double) end - start) / CLOCKS_PER_SEC;
                    ++NUM_RSA_GENERATES;
                }
            #endif
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
        if (pub_key == nullptr)
        {
            Log::Line(Log::EMERG, "RsaWrappers::CreatePublicKey: RSA_new failed: %s", ERR_error_string(ERR_get_error(), NULL));
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // copy over public elements
        pub_key->n = BN_dup(priv_key->n);
        pub_key->e = BN_dup(priv_key->e);

        exit:
            FUNCTION_END;
    }

    int RsaWrappers::SignatureLength(const RSA* const priv_key)
    {
        if (priv_key == nullptr)
        {
            return NULL_ARG;
        }
        else if (RSA_check_key(priv_key) != 1)
        {
            return INVALID_ARG;
        }
        else
        {
            return RSA_size(priv_key);
        }
    }

    int RsaWrappers::CreateSignedDigest(RSA* priv_key, const unsigned char* msg,
                                        const unsigned int msg_length, unsigned char*& sig,
                                        unsigned int& sig_len)
    {
        FUNCTION_START;

        #ifdef EVALUATE
            clock_t start = clock();
        #endif

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
        if (sig == nullptr)
        {
            sig = (unsigned char*)malloc(RSA_size(priv_key));
            if (sig == nullptr)
            {
                Log::Line(Log::EMERG, "RsaWrappers::CreateSignedDigest: malloc failed to allocate %lu bytes for signature, returned NULL",
                          RSA_size(priv_key));
                RETURN_STATUS(MALLOC_FAILURE);
            }
        }
        else if (sig_len < (unsigned int)RSA_size(priv_key))
        {
            Log::Line(Log::WARN, "RsaWrappers::CreateSignedDigest: sig was of insufficient size: %lu, needed %lu",
                      sig_len, RSA_size(priv_key));
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }

        returned_value = RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sig, &sig_len, priv_key);
        if (returned_value != 1)
        {
            Log::Line(Log::EMERG, "RsaWrappers::CreateSignedDigest: RSA_sign failed, returned: %d, error: %s", status, ERR_error_string(ERR_get_error(), NULL));
            RETURN_STATUS(OPENSSL_ERROR);
        }

        exit:
            #ifdef EVALUATE
                if (status == SUCCESS)
                {
                    clock_t end = clock();
                    TIME_RSA_SIGNS += ((double) end - start) / CLOCKS_PER_SEC;
                    ++NUM_RSA_SIGNS;
                }
            #endif
            FUNCTION_END;
    }

    int RsaWrappers::VerifySignedDigest(RSA* pub_key, const unsigned char* msg,
                                        const unsigned int msg_length, const unsigned char* sig,
                                        const unsigned int sig_len)
    {
        FUNCTION_START;
        unsigned char* digest = nullptr;

        #ifdef EVALUATE
            clock_t start = clock();
        #endif

        if (pub_key == nullptr || msg == nullptr || sig == nullptr)
        {
            RETURN_STATUS(NULL_ARG);
        }
        else if (sig_len != (unsigned)RSA_size(pub_key))
        {
            RETURN_STATUS(INVALID_ARG);
        }

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
            #ifdef EVALUATE
                if (status == SUCCESS)
                {
                    clock_t end = clock();
                    TIME_RSA_VERIFIES += ((double) end - start)/ CLOCKS_PER_SEC;
                    ++NUM_RSA_VERIFIES;
                }
            #endif
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

        #ifdef EVALUATE
            clock_t start = clock();
        #endif

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
            #ifdef EVALUATE
                if (status == SUCCESS)
                {
                    clock_t end = clock();
                    TIME_RSA_ENCRYPTS += ((double) end - start)/ CLOCKS_PER_SEC;
                    ++NUM_RSA_ENCRYPTS;
                }
            #endif
            if (status != SUCCESS)
            {
                free(result);
            }
            FUNCTION_END;
    }

    int RsaWrappers::Decrypt(RSA* key, const unsigned char* msg, const unsigned int msg_len, unsigned char*& result, unsigned int* result_len)
    {
        FUNCTION_START;

        #ifdef EVALUATE
            clock_t start = clock();
        #endif

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
            // decrypt private
            returned_value = RSA_private_decrypt(msg_len, msg, result, key, RSA_PKCS1_PADDING);
            if (returned_value < 0)
            {
                Log::Line(Log::EMERG, "RsaWrappers::Decrypt: RSA_private_decrypt failed, returned status %d with error %s", returned_value, ERR_error_string(ERR_get_error(), NULL));
                RETURN_STATUS(OPENSSL_ERROR);
            }
        }
        else if (returned_value == 0)
        {
            // decrypt public
            returned_value = RSA_public_decrypt(msg_len, msg, result, key, RSA_PKCS1_PADDING);
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
            #ifdef EVALUATE
                if (status == SUCCESS)
                {
                    clock_t end = clock();
                    TIME_RSA_DECRYPTS += ((double) end - start) / CLOCKS_PER_SEC;
                    ++NUM_RSA_DECRYPTS;
                }
            #endif
            if (status != SUCCESS)
            {
                free(result);
            }
            FUNCTION_END;
    }

    int RsaWrappers::CopyKey(const RSA* const from, RSA*& to)
    {
        FUNCTION_START;

        if (from == nullptr)
        {
            Log::Line(Log::WARN, "RsaWrappers::CopyKey: from is null");
            RETURN_STATUS(NULL_ARG);
        }

        to = RSA_new();
        if (to == nullptr)
        {
            Log::Line(Log::EMERG, "RsaWrappers::CopyKey: RSA_new failed: %s", ERR_error_string(ERR_get_error(), NULL));
            RETURN_STATUS(OPENSSL_ERROR);
        }

        to->n = BN_dup(from->n);
        to->e = BN_dup(from->e);
        to->d = BN_dup(from->d);
        to->p = BN_dup(from->p);
        to->q = BN_dup(from->q);
        to->dmp1 = BN_dup(from->dmp1);
        to->dmq1 = BN_dup(from->dmq1);
        to->iqmp = BN_dup(from->iqmp);

        exit:
            if (status != SUCCESS)
            {
                RSA_free(to);
            }
            FUNCTION_END;
    }


    int RsaWrappers::KeysEqual(const RSA* const a, const RSA* const b)
    {
        if (a == b ||
            (BN_cmp(a->n, b->n) == 0 &&
            BN_cmp(a->e, b->e) == 0 &&
            BN_cmp(a->d, b->d) == 0 &&
            BN_cmp(a->p, b->p) == 0 &&
            BN_cmp(a->q, b->q) == 0 &&
            BN_cmp(a->dmp1, b->dmp1) == 0 &&
            BN_cmp(a->dmq1, b->dmq1) == 0 &&
            BN_cmp(a->iqmp, b->iqmp) == 0))
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }

    int RsaWrappers::PublicKeyToString(const RSA* const key, std::string& str)
    {
        FUNCTION_START;
        char* n = nullptr;
        char* e = nullptr;

        // check args
        if (key == nullptr)
        {
            RETURN_STATUS(NULL_ARG);
        }

        // both public elements must be present
        if (key->n == nullptr || key->e == nullptr)
        {
            RETURN_STATUS(INVALID_ARG);
        }

        // empty the string
        if (str.empty() == false)
        {
            str.erase();
        }

        // append n
        n = BN_bn2hex(key->n);
        if (n == nullptr)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }
        str.append(n);

        // append '-'
        str.append("-");

        // append e
        e = BN_bn2hex(key->e);
        if (e == nullptr)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }
        str.append(e);

        exit:
            OPENSSL_free(n);
            OPENSSL_free(e);
            FUNCTION_END;
    }

    int RsaWrappers::StringToPublicKey(const std::string& str, RSA*& key)
    {
        FUNCTION_START;
        BIGNUM* n_bn = nullptr;
        BIGNUM* e_bn = nullptr;
        std::string n_string;
        std::string e_string;
        size_t split = 0;
        size_t split2 = 0;

        if (str.empty())
        {
            RETURN_STATUS(INVALID_ARG);
        }

        // split strings
        split = str.find('-');
        if (split == std::string::npos)
        {
            RETURN_STATUS(INVALID_ARG);
        }
        n_string = str.substr(0, split);

        // ensure only one - is in the string
        split2 = str.find('-', split + 1);
        if (split2 != std::string::npos)
        {
            RETURN_STATUS(INVALID_ARG);
        }
        e_string = str.substr(split + 1);

        // create BN for n
        returned_value = BN_hex2bn(&n_bn, n_string.c_str());
        if (returned_value < 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // create BN for e
        returned_value = BN_hex2bn(&e_bn, e_string.c_str());
        if (returned_value < 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // allocate key
        key = RSA_new();
        if (key == nullptr)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // set n and e
        key->n = n_bn;
        key->e = e_bn;

        exit:
            if (status != SUCCESS)
            {
                BN_free(n_bn);
                BN_free(e_bn);
                RSA_free(key);
            }
            FUNCTION_END;
    }

    int RsaWrappers::PrivateKeyToString(const RSA* const key, std::string& str)
    {
        FUNCTION_START;
        char* num = nullptr;

        // check args
        if (key == nullptr)
        {
            RETURN_STATUS(NULL_ARG);
        }

        // private elements must be present
        returned_value = IsPrivateKey(key);
        if (returned_value == 0)
        {
            RETURN_STATUS(INVALID_ARG);
        }
        else if (returned_value < 0)
        {
            RETURN_STATUS(returned_value);
        }

        // empty the string
        if (str.empty() == false)
        {
            str.erase();
        }

        // append n
        num = BN_bn2hex(key->n);
        if (num == nullptr)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }
        str.append(num);
        OPENSSL_free(num);

        // append '-'
        str.append("-");

        // append e
        num = BN_bn2hex(key->e);
        if (num == nullptr)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }
        str.append(num);
        OPENSSL_free(num);

        // append '-'
        str.append("-");

        // append d
        num = BN_bn2hex(key->d);
        if (num == nullptr)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }
        str.append(num);
        OPENSSL_free(num);

        // append '-'
        str.append("-");

        // append p if it's present in the key
        if (key->p != nullptr)
        {
            num = BN_bn2hex(key->p);
            if (num == nullptr)
            {
                RETURN_STATUS(OPENSSL_ERROR);
            }
            str.append(num);
            OPENSSL_free(num);
        }

        // append '-'
        str.append("-");

        // append q if it's present in the key
        if (key->q != nullptr)
        {
            num = BN_bn2hex(key->q);
            if (num == nullptr)
            {
                RETURN_STATUS(OPENSSL_ERROR);
            }
            str.append(num);
            OPENSSL_free(num);
        }

        // append '-'
        str.append("-");

        // append dmp1 if it's present in the key
        if (key->dmp1 != nullptr)
        {
            num = BN_bn2hex(key->dmp1);
            if (num == nullptr)
            {
                RETURN_STATUS(OPENSSL_ERROR);
            }
            str.append(num);
            OPENSSL_free(num);
        }

        // append '-'
        str.append("-");

        // append dmq1 if it's present in the key
        if (key->dmq1 != nullptr)
        {
            num = BN_bn2hex(key->dmq1);
            if (num == nullptr)
            {
                RETURN_STATUS(OPENSSL_ERROR);
            }
            str.append(num);
            OPENSSL_free(num);
        }

        // append '-'
        str.append("-");

        // append iqmp if it's present in the key
        if (key->iqmp != nullptr)
        {
            num = BN_bn2hex(key->iqmp);
            if (num == nullptr)
            {
                RETURN_STATUS(OPENSSL_ERROR);
            }
            str.append(num);
            OPENSSL_free(num);
        }

        exit:
            FUNCTION_END;
    }

    int RsaWrappers::StringToPrivateKey(const std::string& str, RSA*& key)
    {
        FUNCTION_START;
        std::string num;
        size_t begin = 0;
        size_t end = 0;

        if (str.empty() == true)
        {
            RETURN_STATUS(INVALID_ARG);
        }

        // allocate key
        key = RSA_new();
        if (key == nullptr)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // parse n
        begin = 0;
        end = str.find('-');
        if (end == std::string::npos)
        {
            RETURN_STATUS(INVALID_ARG);
        }
        num = str.substr(begin, end - begin);
        returned_value = BN_hex2bn(&key->n, num.c_str());
        if (returned_value < 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // parse e
        begin = end + 1;
        end = str.find('-', begin);
        if (end == std::string::npos)
        {
            RETURN_STATUS(INVALID_ARG);
        }
        num = str.substr(begin, end - begin);
        returned_value = BN_hex2bn(&key->e, num.c_str());
        if (returned_value < 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // parse d
        begin = end + 1;
        end = str.find('-', begin);
        if (end == std::string::npos)
        {
            RETURN_STATUS(INVALID_ARG);
        }
        num = str.substr(begin, end - begin);
        returned_value = BN_hex2bn(&key->d, num.c_str());
        if (returned_value < 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // parse p
        begin = end + 1;
        end = str.find('-', begin);
        if (end == std::string::npos)
        {
            RETURN_STATUS(INVALID_ARG);
        }
        num = str.substr(begin, end - begin);
        returned_value = BN_hex2bn(&key->p, num.c_str());
        if (returned_value < 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // parse q
        begin = end + 1;
        end = str.find('-', begin);
        if (end == std::string::npos)
        {
            RETURN_STATUS(INVALID_ARG);
        }
        num = str.substr(begin, end - begin);
        returned_value = BN_hex2bn(&key->q, num.c_str());
        if (returned_value < 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // parse dmp1
        begin = end + 1;
        end = str.find('-', begin);
        if (end == std::string::npos)
        {
            RETURN_STATUS(INVALID_ARG);
        }
        num = str.substr(begin, end - begin);
        returned_value = BN_hex2bn(&key->dmp1, num.c_str());
        if (returned_value < 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // parse dmq1
        begin = end + 1;
        end = str.find('-', begin);
        if (end == std::string::npos)
        {
            RETURN_STATUS(INVALID_ARG);
        }
        num = str.substr(begin, end - begin);
        returned_value = BN_hex2bn(&key->dmq1, num.c_str());
        if (returned_value < 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        // parse iqmp
        begin = end + 1;
        end = str.find('-', begin);
        if (end != std::string::npos)
        {
            // in this case, if there IS another segment,
            // it's incorrect and we should fail
            RETURN_STATUS(INVALID_ARG);
        }
        // take substring to the end of the string
        num = str.substr(begin);
        returned_value = BN_hex2bn(&key->iqmp, num.c_str());
        if (returned_value < 1)
        {
            RETURN_STATUS(OPENSSL_ERROR);
        }

        exit:
            if (status != SUCCESS)
            {
                RSA_free(key);
            }
            FUNCTION_END;
    }
}
