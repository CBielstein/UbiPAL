// Cameron Bielstein, 2/14/15
// ase_wrappers.h
// Wrapper functions for OpenSSL's symmetric encryption and decryption algorithms

#ifndef UBIPAL_SRC_AES_WRAPPERS_H
#define UBIPAL_SRC_AES_WRAPPERS_H

// standard
#include <string>

// Using 256 bit keys
#define AES_KEYLEN 256

namespace UbiPAL
{
    // AesWrappers
    // A collection of functions that wrap around the AES functions in OpenSSL for convenience and consolidation of implementation
    class AesWrappers
    {
        public:
            // GenerateAesObject
            // generates an aes key or iv
            // args
            //      [OUT] obj: either the key or iv
            //      [OUT] obj_len: the length of obj, if not null
            // return
            //      int: SUCCESS on success, error code otherwise
            static int GenerateAesObject(unsigned char*& obj, int* obj_len);

            // AesObjectsEqual
            // Compares keys and checks if they are the same object (key or IV), even if the pointers are different
            // args
            //          [IN] a: The first AES object to compare
            //          [IN] b: The second AES object to compare
            // return
            //          int: 1 if the objects match, 0 if they don't, < 0 error on failure
            static int AesObjectsEqual(const unsigned char* const a, const unsigned char* const b);

            // ObjectToString
            // Creates a string representation of the given object
            //          [IN] obj: The object
            //          [OUT] str: The string which will hold the representation
            // return
            //          int: SUCCESS on success, negative error otherwise
            static int ObjectToString(const unsigned char* const obj, std::string& str);

            // StringToObject
            // Allocates and creates an AES object from the given string
            // args
            //          [IN] str: the string representing the object
            //          [OUT] key: a pointer to allocate and set the object
            // return
            //          int: SUCCESS on success, negative error otherwise
            static int StringToObject(const std::string& str, unsigned char*& key);

            // Encrypt
            // Encrypts a message with a given AES key and iv
            // args
            //      [IN] key: AES key to use for encryption
            //      [IN] iv: IV to use for encryption
            //      [IN] msg: Bytes to encrypt
            //      [IN] msg_len: The number of bytes to encrypt
            //      [OUT] result: The result of the encryption
            //      [OUT] result_len: The number of bytes encrypted, if not NULL
            // return
            //      int: SUCCESS on success, error code otherwise
            static int Encrypt(const unsigned char* const key, const unsigned char* const iv,
                               const unsigned char* const msg, const unsigned int& msg_len, unsigned char*& result, unsigned int* result_len);

            // Decrypt
            // detects whether the given key is private or public and calls the appropriate OpenSSL function, placing the result in the pointer at result
            // args
            //      [IN] key: AES key to use for decryption
            //      [IN] iv: IV to use for decryption
            //      [IN] msg: Bytes to decrypt
            //      [IN] msg_len: Number of bytes to decrypt
            //      [OUT] result: The result of the decryption
            //      [OUT] result_len: The number of bytes decrypted, if not NULL
            // return
            //      int: SUCCESS on success, error code otherwise
            static int Decrypt(const unsigned char* const key, const unsigned  char* const iv,
                               const unsigned char* const msg, const unsigned int& msg_len, unsigned char*& result, unsigned int* result_len);
    };
}
#endif
