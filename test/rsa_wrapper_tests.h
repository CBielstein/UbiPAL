// Cameron Bielstein, 1/1/15
// rsa_wrapper_tests.h
// Holds unit tests for RSA_wrappers class for UbiPAL

#ifndef RSA_WRAPPERS_TESTS_H
#define RSA_WRAPPERS_TESTS_H

#include "../src/rsa_wrappers.h"
#include <string.h>
#include "../src/error.h"
#include "test_helpers.h"

namespace UbiPAL
{
    class RSA_wrapper_tests
    {
        private:
            // Unit tests

            // signed by private, verified by public
            static int rsa_wrapper_basic();
            // signed by private, failed verification by wrong public key
            static int rsa_wrapper_wrong_pub_key();
            // signed by private, failed verification by wrong private key
            static int rsa_wrapper_wrong_priv_key();
            static int rsa_wrapper_is_private_true();
            static int rsa_wrapper_is_private_false();
            // encrypt public, decrypt private
            static int rsa_wrapper_encrypt_decrypt_basic();
            // encrypt private, decrypt public
            static int rsa_wrapper_encrypt_decrypt_basic_reverse();
            // encrypt public, decrypt wrong private and fail
            static int rsa_wrapper_encrypt_decrypt_wrongkey();
            // encrypt private, decrypt wrong public and fail
            static int rsa_wrapper_encrypt_decrypt_wrongkey_reverse();
            // encrypt private, decrypt public
            static int rsa_wrapper_encrypt_decrypt_public_fail();

            // End unit tests
        public:
            // Envoke all unit tests in this class
            static void rsa_wrapper_tests(unsigned int& module_count, unsigned int& module_fails);
    };
}
#endif
