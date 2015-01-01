// Test code to get rsa public key encryption working

#ifndef RSA_WRAPPERS_TESTS_CPP
#define RSA_WRAPPERS_TESTS_CPP

#include "../src/rsa_wrappers.h"
#include <string.h>
#include "test_helpers.cpp"
#include "error.h"

namespace UbiPAL
{
    class RSA_wrapper_tests
    {
        private:
            // signed by private, verified by public
            static int rsa_wrapper_basic()
            {
                int status = SUCCESS;
                unsigned char* sig;
                unsigned int sig_len;

                // create message
                const char* msg = "Hello, is it me you're looking for?";

                // get key pair
                RSA* priv;
                RSA* pub;
                status = RSA_wrappers::generate_rsa_key(priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_basic: Error in generate_rsa_key: %d\n", status);
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(priv, pub);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_basic: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                // create message signature
                status = RSA_wrappers::create_signed_digest(priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_basic: Error in create_signed_digest: %d\n", status);
                    goto exit;
                }

                // Test verification
                status = RSA_wrappers::verify_signed_digest(pub, (unsigned char*)msg, strlen(msg), sig, sig_len);
                if (status != 1)
                {
                    fprintf(stderr, "rsa_wrapper_basic: Failed to validate signature with status %d\n", status);
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
            static int rsa_wrapper_wrong_pub_key()
            {
                int status = SUCCESS;
                unsigned char* sig;
                unsigned int sig_len;

                // create message
                const char* msg = "It Came Upon A Midnight Clear";

                // get key pair
                RSA* priv;
                RSA* pub;
                status = RSA_wrappers::generate_rsa_key(priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_pub_key: Error in generate_rsa_key: %d\n", status);
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(priv, pub);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_pub_key: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                // create message signature
                status = RSA_wrappers::create_signed_digest(priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_pub_key: Error in create_signed_digest: %d\n", status);
                    goto exit;
                }

                // get wrong keypair
                RSA* wrong_priv;
                RSA* wrong_pub;
                status = RSA_wrappers::generate_rsa_key(wrong_priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_pub_key: Error in generate_rsa_key: %d\n", status);
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(wrong_priv, wrong_pub);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_pub_key: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                // Test verification
                status = RSA_wrappers::verify_signed_digest(wrong_pub, (unsigned char*)msg, strlen(msg), sig, sig_len);
                if (status == 1)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_pub_key: Incorrectly validated signature with different public key\n");
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
            static int rsa_wrapper_wrong_priv_key()
            {
                int status = SUCCESS;
                unsigned char* sig;
                unsigned int sig_len;

                // create message
                const char* msg = "Sleighbells in the air, beauty everywhere. Yule tide by the fireside and joyful memories there. Christmas time is here.";

                // get key pair
                RSA* priv;
                RSA* pub;
                status = RSA_wrappers::generate_rsa_key(priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_priv_key: Error in generate_rsa_key: %d\n", status);
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(priv, pub);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_priv_key: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                // create message signature
                status = RSA_wrappers::create_signed_digest(priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_priv_key: Error in create_signed_digest: %d\n", status);
                    goto exit;
                }

                // get wrong keypair
                RSA* wrong_priv;
                RSA* wrong_pub;
                status = RSA_wrappers::generate_rsa_key(wrong_priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_priv_key: Error in generate_rsa_key: %d\n", status);
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(wrong_priv, wrong_pub);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_priv_key: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                // Test verification
                status = RSA_wrappers::verify_signed_digest(wrong_priv, (unsigned char*)msg, strlen(msg), sig, sig_len);
                if (status == 1)
                {
                    fprintf(stderr, "rsa_wrapper_wrong_priv_key: Incorrectly validated signature with different public key\n");
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

            static int rsa_wrapper_is_private_true()
            {
                int status = SUCCESS;

                RSA* priv;
                status = RSA_wrappers::generate_rsa_key(priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_is_private_true: Failed to generate a public key.\n");
                    goto exit;
                }

                status = RSA_wrappers::is_private_key(priv);
                if (status != 1)
                {
                    fprintf(stderr, "rsa_wrapper_is_private_true: is_private_key failed to identify private key. Returned %d\n", status);
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

            static int rsa_wrapper_is_private_false()
            {
                int status = SUCCESS;

                RSA* priv;
                RSA* pub;
                status = RSA_wrappers::generate_rsa_key(priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_is_private_true: Failed to generate a public key.\n");
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(priv, pub);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_basic: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                status = RSA_wrappers::is_private_key(pub);
                if (status != 0)
                {
                    fprintf(stderr, "rsa_wrapper_is_private_true: is_private_key wrongly identified private key. Returned %d\n", status);
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

            // encrypt public, decrypt private
            static int rsa_wrapper_encrypt_decrypt_basic()
            {
                int status = SUCCESS;

                // create message
                const char* msg = "Buddy the Elf, what's your favorite color?";

                // create keypair
                RSA* priv;
                RSA* pub;
                status = RSA_wrappers::generate_rsa_key(priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_basic: Failed to generate a public key.\n");
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(priv, pub);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_basic: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                // encrypt
                unsigned char* result;
                unsigned int bytes_encrypted;
                status = RSA_wrappers::encrypt(pub, (unsigned char*)msg, strlen(msg), result, &bytes_encrypted);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_basic: Error in encrypt: %d, %d bytes encrypted\n", status, bytes_encrypted);
                    goto exit;
                }

                // decrypt
                unsigned char* result_msg;
                unsigned int bytes_decrypted;
                status = RSA_wrappers::decrypt(priv, result, result_msg, &bytes_decrypted);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_basic: Error in decrypt: %d, %d bytes decrypted\n", status, bytes_decrypted);
                    goto exit;
                }

                // compare
                status = memcmp(msg, result_msg, bytes_decrypted);
                if (status != 0 || strlen(msg) != bytes_decrypted)
                {
                    fprintf(stderr, "rsa_wrapper_encryp_decrypt_basic: Strings don't match: %s, %s or lengths don't match: %lu, %d\n",
                            msg, result_msg, strlen(msg), bytes_decrypted);
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

            // encrypt private, decrypt public
            static int rsa_wrapper_encrypt_decrypt_basic_reverse()
            {
                int status = SUCCESS;

                // create message
                const char* msg = "Peter Piper picked a peck of pickled peppers.";

                // create keypair
                RSA* priv;
                RSA* pub;
                status = RSA_wrappers::generate_rsa_key(priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_basic_reverse: Failed to generate a public key.\n");
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(priv, pub);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_basic_reverse: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                // encrypt
                unsigned char* result;
                unsigned int bytes_encrypted;
                status = RSA_wrappers::encrypt(priv, (unsigned char*)msg, strlen(msg), result, &bytes_encrypted);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_basic_reverse: Error in encrypt: %d, %d bytes encrypted\n", status, bytes_encrypted);
                    goto exit;
                }

                // decrypt
                unsigned char* result_msg;
                unsigned int bytes_decrypted;
                status = RSA_wrappers::decrypt(pub, result, result_msg, &bytes_decrypted);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_basic_reverse: Error in decrypt: %d, %d bytes decrypted\n", status, bytes_decrypted);
                    goto exit;
                }

                // compare
                status = memcmp(msg, result_msg, bytes_decrypted);
                if (status != 0 || strlen(msg) != bytes_decrypted)
                {
                    fprintf(stderr, "rsa_wrapper_encryp_decrypt_basic_reverse: Strings don't match: %s, %s, or lengths don't match: %lu/%d\n",
                            msg, result_msg, strlen(msg), bytes_decrypted);
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

            // encrypt public, decrypt wrong private and fail
            static int rsa_wrapper_encrypt_decrypt_wrongkey()
            {
                int status = SUCCESS;

                // create message
                const char* msg = "Peter Piper picked a peck of pickled peppers.";

                // create keypair
                RSA* priv;
                RSA* pub;
                status = RSA_wrappers::generate_rsa_key(priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_wrongkey: Failed to generate a public key.\n");
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(priv, pub);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_wrongkey: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                // create second key
                RSA* priv_wrong;
                status = RSA_wrappers::generate_rsa_key(priv_wrong);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_wrongkey: Failed to generate a public key.\n");
                    goto exit;
                }

                // encrypt
                unsigned char* result;
                unsigned int bytes_encrypted;
                status = RSA_wrappers::encrypt(pub, (unsigned char*)msg, strlen(msg), result, &bytes_encrypted);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_wrongkey: Error in encrypt: %d, %d bytes encrypted\n", status, bytes_encrypted);
                    goto exit;
                }

                // decrypt with wrong key
                unsigned char* result_msg;
                unsigned int bytes_decrypted;
                status = RSA_wrappers::decrypt(priv_wrong, result, result_msg, &bytes_decrypted);
                if (status == SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_wrongkey: Decrypt wrongly succeeded: %d, %d bytes decrypted\n", status, bytes_decrypted);
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

            // encrypt private, decrypt wrong public and fail
            static int rsa_wrapper_encrypt_decrypt_wrongkey_reverse()
            {
                int status = SUCCESS;

                // create message
                const char* msg = "Everything is bigger in Texas!";

                // create key
                RSA* priv;
                status = RSA_wrappers::generate_rsa_key(priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_wrongkey_reverse: Failed to generate a public key.\n");
                    goto exit;
                }

                // create wrong keypair
                RSA* priv_wrong;
                RSA* pub_wrong;
                status = RSA_wrappers::generate_rsa_key(priv_wrong);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_wrongkey_reverse: Failed to generate a public key.\n");
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(priv_wrong, pub_wrong);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_wrongkey_reverse: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                // encrypt
                unsigned char* result;
                unsigned int bytes_encrypted;
                status = RSA_wrappers::encrypt(priv, (unsigned char*)msg, strlen(msg), result, &bytes_encrypted);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_wrongkey_reverse: Error in encrypt: %d, %d bytes encrypted\n", status, bytes_encrypted);
                    goto exit;
                }

                // decrypt with wrong key
                unsigned char* result_msg;
                unsigned int bytes_decrypted;
                status = RSA_wrappers::decrypt(pub_wrong, result, result_msg, &bytes_decrypted);
                if (status == SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_wrongkey_reverse: Decrypt wrongly succeeded: %d, %d bytes decrypted\n", status, bytes_decrypted);
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

            // encrypt private, decrypt public
            static int rsa_wrapper_encrypt_decrypt_public_fail()
            {
                int status = SUCCESS;

                // create message
                const char* msg = "Peter Piper picked a peck of pickled peppers.";

                // create keypair
                RSA* priv;
                RSA* pub;
                status = RSA_wrappers::generate_rsa_key(priv);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_public_fail: Failed to generate a public key.\n");
                    goto exit;
                }

                status = RSA_wrappers::create_public_key(priv, pub);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_public_fail: Error in create_public_key: %d\n", status);
                    goto exit;
                }

                // encrypt
                unsigned char* result;
                unsigned int bytes_encrypted;
                status = RSA_wrappers::encrypt(pub, (unsigned char*)msg, strlen(msg), result, &bytes_encrypted);
                if (status != SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_public_fail: Error in encrypt: %d, %d bytes encrypted\n", status, bytes_encrypted);
                    goto exit;
                }

                // decrypt
                unsigned char* result_msg;
                unsigned int bytes_decrypted;
                status = RSA_wrappers::decrypt(pub, result, result_msg, &bytes_decrypted);
                if (status == SUCCESS)
                {
                    fprintf(stderr, "rsa_wrapper_encrypt_decrypt_public_fail: Incorrectly succeeded in decrypt: %d, %d bytes decrypted\n", status, bytes_decrypted);
                    goto exit;
                }

                status = SUCCESS;

                exit:
                    RSA_free(priv);
                    RSA_free(pub);
                    free(result);
                    return status;
            }

        public:
            static void rsa_wrapper_tests(unsigned int& module_count, unsigned int& module_fails)
            {
                run_test_func(rsa_wrapper_basic, SUCCESS, "rsa_wrapper_basic", module_count, module_fails);
                run_test_func(rsa_wrapper_wrong_pub_key, SUCCESS, "rsa_wrapper_wrong_pub_key", module_count, module_fails);
                run_test_func(rsa_wrapper_wrong_priv_key, SUCCESS, "rsa_wrapper_wrong_priv_key", module_count, module_fails);
                run_test_func(rsa_wrapper_is_private_true, SUCCESS, "rsa_wrapper_is_private_true", module_count, module_fails);
                run_test_func(rsa_wrapper_is_private_false, SUCCESS, "rsa_wrapper_is_private_false", module_count, module_fails);
                run_test_func(rsa_wrapper_encrypt_decrypt_basic, SUCCESS, "rsa_wrapper_encrypt_decrypt_basic", module_count, module_fails);
                run_test_func(rsa_wrapper_encrypt_decrypt_basic_reverse, SUCCESS, "rsa_wrapper_encrypt_decrypt_basic_reverse", module_count, module_fails);
                run_test_func(rsa_wrapper_encrypt_decrypt_wrongkey, SUCCESS, "rsa_wrapper_encrypt_decrypt_wrongkey", module_count, module_fails);
                run_test_func(rsa_wrapper_encrypt_decrypt_wrongkey_reverse, SUCCESS, "rsa_wrapper_encrypt_decrypt_wrongkey_reverse", module_count, module_fails);
                run_test_func(rsa_wrapper_encrypt_decrypt_public_fail, SUCCESS, "rsa_wrapper_encrypt_decrypt_public_fail", module_count, module_fails);
            }
    };
}
#endif
