// Cameron Bielstein, 1/14/15
// messages.h
// Message types and certificates for UbiPAL

#ifndef UBIPAL_SRC_MESSAGES_H
#define UBIPAL_SRC_MESSAGES_H

#define MAX_MESSAGE_SIZE 1024

// ubipal
#include "rsa_wrappers.h"

// standard
#include <stdint.h>
#include <string>

/** Network encoding takes the following formats. This is to be used as a reference for encode and decode functions. They should do the rest.
All types should use the appropriate translations to and from network types for endian correctness

BaseMessage:
    1 byte: type
    4 bytes: length_to, length of name dest address in bytes
    length_to bytes: name of dest
    4 bytes: length_from, length of name of sender address in bytes
    length_from bytes: name of source

Message: above, plus the following
    4 bytes: msg_len uint32_t
    msg_len bytes: message char*
    4 bytes: arg_len uint32_t
    arg_len bytes: arg char*

**/


namespace UbiPAL
{
    enum MessageType
    {
        MESSAGE = 1,
        NAMESPACE_CERTIFICATE = 2,
        ACCESS_CONTROL_LIST = 3,
    };

    struct BaseMessage
    {
        uint8_t type;
        std::string to;
        std::string from;

        // Encode
        // Takes a buffer buf of length buf_len and outputs an array of bytes representing this message type.
        // If the buffer is too short, additional data is truncated
        // args
        //      [IN/OUT] buf: the buffer in which to place the resulting bytes
        //      [IN] buf_len: The length of the buffer. This ensures it's of appropriate length
        // return
        //      int: the length of the resulting bytes, or a negative error code
        virtual int Encode(char* const buf, const uint32_t buf_len);

        // Decode
        // Takes a buffer buf of length buf_len and decodes the data to the fields in this message type.
        // args
        //      [IN] buf: the buffer of bytes to decode
        //      [IN] buf_len: The length of the bytes to decode
        // return
        //      int: The number of bytes used, negative error code otherwise
        virtual int Decode(const char* const buf, const uint32_t buf_len);

        // EncodedLength
        // Returns the number of bytes required to encode this message
        // return
        //      int: the number of bytes required to encode this message, or a negative error code
        virtual int EncodedLength();
    };

    // Message
    // A message sent from one UbipalName to another requesting action or information
    struct Message : BaseMessage
    {
        std::string message;
        uint32_t arg_len;
        char* argument;

        Message();
        Message(const char* const arg, const uint32_t arg_size);
        ~Message();

        virtual int Encode(char* const buf, const uint32_t buf_len);
        virtual int Decode(const char* const buf, const uint32_t buf_len);
        virtual int EncodedLength();
    };

    struct NamespaceCertificate : BaseMessage
    {
        std::string name;
        std::string address;
        std::string port;
        RSA* public_key;
        std::string signer;
        char* signature;

        NamespaceCertificate();

        //virtual int Encode(char* const buf, const uint32_t buf_len);
        //virtual int Decode(const char* const buf, const uint32_t buf_len);
    };

    struct AccessControlList : BaseMessage
    {
        uint32_t rules_length;
        char* rules;

        AccessControlList();

        //virtual int Encode(char* const buf, const uint32_t buf_len);
        //virtual int Decode(const char* const buf, const uint32_t buf_len);
    };
}

#endif
