// Cameron Bielstein, 12/23/14
// rsa_wrappers.h
// Wrapper functions for OpenSSL's RSA encryption and verification algorithms

#ifndef UBIPAL_SRC_RSA_WRAPPERS_H
#define UBIPAL_SRC_RSA_WRAPPERS_H

// UbiPAL includes
#include "error.h"

// OpenSSL includes
#include <openssl/rsa.h>

// standard
#include <string>

namespace UbiPAL
{
    // RsaWrappers
    // A collection of functions that wrap around the RSA functions in OpenSSL for convenience and consolidation of implementation
    class RsaWrappers
    {
        public:
            // GenerateRsaKey
            // generates an rsa private key using e == 3
            // args
            //      [OUT] rsa: RSA* by reference. This will be allocated and fields set to generated key
            // return
            //      int: SUCCESS on success, error code otherwise
            static int GenerateRsaKey(RSA*& rsa);

            // CreatePublicKey
            // Stores a public key version of priv_key in pub_key.
            // This means all values not explicitly marked public in the RSA OpenSSL docs are set to NULL
            // args
            //      [IN] priv_key: Previously generated RSA struct
            //      [OUT] pub_key: RSA* where new key will be allocated and fields set
            // return
            //      int: SUCCESS on success, error code otherwise
            static int CreatePublicKey(const RSA* priv_key, RSA*& pub_key);

            // SignatureLength
            // Computes the number of bytes needed for a signature with a given private key
            // args
            //          [IN] priv_key: The private key which will be used to create the signature
            // return
            //          int: The number of bytes needed for a signature, or negative error code on a failure
            static int SignatureLength(const RSA* const priv_key);

            // CreateSignedDigest
            // given the appropriate args, hashes and signs a digest, which is stores in sig, with a length stored in sig_len
            // digest uses SHA1
            // args
            //      [IN] priv_key: the RSA struct to use for signing, must be full private key, not public key
            //      [IN] msg: byte array of data to sign
            //      [IN] msg_length: number of bytes of msg
            //      [IN/OUT] sig: the memory for the signed digest. If null, space is allocated
            //      [IN/OUT] sig_len: passes in the length of sig (if non-null),
            //                        and is set to the length of the signed digest (also RSA_size(priv_key))
            // return
            //      int: SUCCESS on success, error code otherwise
            static int CreateSignedDigest(RSA* priv_key, const unsigned char* msg, const unsigned int msg_length, unsigned char*& sig, unsigned int& sig_len);

            // VerifySignedDigest
            // give the appropriate args, hashes the data and compares it to the signed sig
            // hash/digest uses SHA1
            // args
            //      [IN] pub_key: the RSA struct to use for validation. Can be public key or have all fields (private key). Private keys will run faster.
            //      [IN] msg: bytes to validate against
            //      [IN] msg_length: number of bytes to validate against
            //      [IN] sig: signature to validate
            //      [IN] sig_len: length of signature to validate
            // return
            //      int: 1 on successful validation, 0 on unsuccessful validation, error code otherwise
            static int VerifySignedDigest(RSA* pub_key, const unsigned char* msg, const unsigned int msg_length, const unsigned char* sig, const unsigned int sig_len);

            // Encrypt
            // detects whether the given key is private or public and calls the appropriate OpenSSL function, placing the result in the pointer at result
            // args
            //      [IN] key: RSA key to use for encryption (may be public or private)
            //      [IN] msg: Bytes to encrypt
            //      [IN] msg_len: The number of bytes to encrypt
            //      [OUT] result: The result of the encryption
            //      [OUT] result_len: The number of bytes encrypted, if not NULL
            // return
            //      int: SUCCESS on success, error code otherwise
            static int Encrypt(RSA* key, const unsigned char* msg, const unsigned int& msg_len, unsigned char*& result, unsigned int* result_len);

            // Decrypt
            // detects whether the given key is private or public and calls the appropriate OpenSSL function, placing the result in the pointer at result
            // args
            //      [IN] key: RSA key to use for decryption (may be public or private)
            //      [IN] msg: Bytes to decrypt
            //      [IN] msg_len: Number of bytes to decrypt
            //      [OUT] result: The result of the decryption
            //      [OUT] result_len: The number of bytes decrypted, if not NULL
            // return
            //      int: SUCCESS on success, error code otherwise
            static int Decrypt(RSA* key, const unsigned char* msg, const unsigned int msg_len, unsigned char*& result, unsigned int* result_len);

            // CopyKey
            // Allocates a to key and duplicates the big number fields in from to to.
            // The result is the same key in a completely disjoint memory location
            // args
            //          [IN] from: The RSA key to duplicate. This may be public or private
            //          [OUT] to: A pointer to the newly allocated and constructed RSA key
            // return
            //          int: SUCCESS on success, negative error code otherwise
            static int CopyKey(const RSA* const from, RSA*& to);

            // KeysEqual
            // Compares keys and checks if they are the same key, even if the pointers are different
            // args
            //          [IN] a: The first RSA key to compare
            //          [IN] b: The second RSA key to compare
            // return
            //          int: 1 if the keys match, 0 if they don't, < 0 error on failure
            static int KeysEqual(const RSA* const a, const RSA* const b);

            // PublicKeyToString
            // Creates a string representation of the public key of the given key
            // Format is "n-e"
            // args
            //          [IN] key: The key
            //          [OUT] str: The string which will hold the representation
            // return
            //          int: SUCCESS on success, negative error otherwise
            static int PublicKeyToString(const RSA* const key, std::string& str);

            // StringToPublicKey
            // Allocates and creates a public key from the given string
            // Format is "n-e"
            // args
            //          [IN] str: the string representing the public key
            //          [OUT] key: a pointer to allocate and set the public key
            // return
            //          int: SUCCESS on success, negative error otherwise
            static int StringToPublicKey(const std::string& str, RSA*& key);

            // PrivateKeyToString
            // Creates a string representation of the given private key
            // Format is "n-e-d-q-p-dmp1-dmq1-iqmp"
            // args
            //          [IN] key: The key
            //          [OUT] str: The string which will hold the representation
            // return
            //          int: SUCCESS on success, negative error otherwise
            static int PrivateKeyToString(const RSA* const key, std::string& str);

            // StringToPrivateKey
            // Allocates and creates a private key from the given string
            // Format is "n-e-d-q-p-dmp1-dmq1-iqmp"
            // args
            //          [IN] str: the string representing the public key
            //          [OUT] key: a pointer to allocate and set the public key
            // return
            //          int: SUCCESS on success, negative error otherwise
            static int StringToPrivateKey(const std::string& str, RSA*& key);

        private:
            // IsPrivateKey
            // determines if a key is private and returns true
            // args
            //      [IN] key: key to check
            // return
            //      int: returns 1 if key is private, 0 otherwise, error code on error
            static int IsPrivateKey(const RSA* key);

            // MaxMessageLength
            // with our padding, we must reserve 11 bits
            // so our message can be no longer than RSA_size(key) - 12 bits long
            // args
            //          [IN] key: The RSA key to be used for computation of message length
            // return
            //          unsigned int: the maximum message size for the given RSA key
            static inline unsigned int MaxMessageLength(const RSA* key)
            {
                if (key == nullptr)
                {
                    return NULL_ARG;
                }
                else
                {
                    return RSA_size(key) - 12;
                }
            }

        // enable testing
        friend class RsaWrappersTests;
    };
}
#endif
