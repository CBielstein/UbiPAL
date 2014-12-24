// Cameron Bielstein, 12/23/14
// rsa_wrappers.h
// Wrapper functions for OpenSSL's RSA encryption and verification algorithms

#ifndef RSA_WRAPPERS_H
#define RSA_WRAPPERS_H

#include <stdlib.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bn.h>

class RSA_wrappers
{
    public:
        // generates an rsa private key, given an allocated rsa structure, using e == 3
        // args
        //      [OUT] rsa: RSA* by reference. This will be allocated and fields set to generated key
        // returns EXIT_SUCCESS on success
        static int generate_rsa_key(RSA*& rsa);

        // given two allocated rsa structures, stores a public key version of priv_key in pub_key.
        // This means all values not explicitly marked public in the RSA OpenSSL docs are set to NULL
        // args
        //      [IN] priv_key: Previously generated RSA struct
        //      [OUT] pub_key: RSA* where new key will be allocated and fields set
        // returns EXIT_SUCCESS on success
        static int create_public_key(const RSA* priv_key, RSA*& pub_key);

        // given the appropriate args, hashes and signs a digest, which is stores in sig, with a length stored in sig_len
        // digest uses SHA1
        // args
        //      [IN] priv_key: the RSA struct to use for signing, must be full private key, not public key
        //      [IN] msg: byte array of data to sign
        //      [IN] msg_length: number of bytes of msg
        //      [OUT] sig: the signed digest
        //      [OUT] sig_len: the length of the signed digest (also RSA_size(priv_key))
        // returns EXIT_SUCCESS on success
        static int create_signed_digest(RSA* priv_key, const unsigned char* msg, const unsigned int msg_length, unsigned char*& sig, unsigned int& sig_len);

        // give the appropriate args, hashes the data and compares it to the signed sig
        // hash/digest uses SHA1
        //args
        //      [IN] pub_key: the RSA struct to use for validation. Can be public key or have all fields (private key). Private keys will run faster.
        //      [IN] msg: bytes to validate against
        //      [IN] msg_length: number of bytes to validate against
        //      [IN] sig: signature to validate
        //      [IN] sig_len: length of signature to validate
        // returns true on successul validation, false on unsuccessful validation
        static bool verify_signed_digest(RSA* pub_key, const unsigned char* msg, const unsigned int msg_length, const unsigned char* sig, const unsigned int sig_len);
};

#endif
