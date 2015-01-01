// Cameron Bielstein, 12/23/14
// rsa_wrappers.h
// Wrapper functions for OpenSSL's RSA encryption and verification algorithms

#ifndef RSA_WRAPPERS_H
#define RSA_WRAPPERS_H

// C library includes
#include <stdlib.h>
#include <stdlib.h>
#include <time.h>

// OpenSSL includes
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bn.h>

// UbiPAL includes
#include "error.h"

namespace UbiPAL
{
    class RSA_wrappers
    {
        public:
            // generate_rsa_key
            // generates an rsa private key, given an allocated rsa structure, using e == 3
            // args
            //      [OUT] rsa: RSA* by reference. This will be allocated and fields set to generated key
            // returns SUCCESS on success
            static int generate_rsa_key(RSA*& rsa);

            // create_public_key
            // given two allocated rsa structures, stores a public key version of priv_key in pub_key.
            // This means all values not explicitly marked public in the RSA OpenSSL docs are set to NULL
            // args
            //      [IN] priv_key: Previously generated RSA struct
            //      [OUT] pub_key: RSA* where new key will be allocated and fields set
            // returns SUCCESS on success
            static int create_public_key(const RSA* priv_key, RSA*& pub_key);

            // create_signed_digest
            // given the appropriate args, hashes and signs a digest, which is stores in sig, with a length stored in sig_len
            // digest uses SHA1
            // args
            //      [IN] priv_key: the RSA struct to use for signing, must be full private key, not public key
            //      [IN] msg: byte array of data to sign
            //      [IN] msg_length: number of bytes of msg
            //      [OUT] sig: the signed digest
            //      [OUT] sig_len: the length of the signed digest (also RSA_size(priv_key))
            // returns SUCCESS on success
            static int create_signed_digest(RSA* priv_key, const unsigned char* msg, const unsigned int msg_length, unsigned char*& sig, unsigned int& sig_len);

            // verify_signed_digest
            // give the appropriate args, hashes the data and compares it to the signed sig
            // hash/digest uses SHA1
            // args
            //      [IN] pub_key: the RSA struct to use for validation. Can be public key or have all fields (private key). Private keys will run faster.
            //      [IN] msg: bytes to validate against
            //      [IN] msg_length: number of bytes to validate against
            //      [IN] sig: signature to validate
            //      [IN] sig_len: length of signature to validate
            // returns 1 on successul validation, 0 on unsuccessful validation
            static int verify_signed_digest(RSA* pub_key, const unsigned char* msg, const unsigned int msg_length, const unsigned char* sig, const unsigned int sig_len);

            // encrypt
            // detects whether the given key is private or public and calls the appropriate OpenSSL function, placing the result in the pointer at result
            // args
            //      [IN] key: RSA key to use for encryption (may be public or private)
            //      [IN] msg: Bytes to encrypt
            //      [IN] msg_len: The number of bytes to encrypt
            //      [OUT] result: The result of the encryption
            //      [OUT] result_len: The number of bytes encrypted, if not NULL
            // returns SUCCESS on success
            static int encrypt(RSA* key, const unsigned char* msg, const unsigned int& msg_len, unsigned char*& result, unsigned int* result_len);

            // decrypt
            // detects whether the given key is private or public and calls the appropriate OpenSSL function, placing the result in the pointer at result
            // args
            //      [IN] key: RSA key to use for decryption (may be public or private)
            //      [IN] msg: Bytes to decrypt
            //      [OUT] result: The result of the decryption
            //      [OUT] result_len: The number of bytes decrypted, if not NULL
            // returns SUCCESS on success
            static int decrypt(RSA* key, const unsigned char* msg, unsigned char*& result, unsigned int* result_len);

        private:
            // is_private_key
            // determines if a key is private and returns true
            // args
            //      [IN] key: key to check
            // returns 1 if key is private, 0 otherwise
            static int is_private_key(const RSA* key);

            // with our padding, we must reserve 11 bits, so our message can be no longer than RSA_size(key) - 12 bits long
            static inline int max_message_length(const RSA* key) { return RSA_size(key) - 12; }

        // enable testing
        friend class RSA_wrapper_tests;
    };
}
#endif
