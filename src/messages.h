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

Message: BaseMessage, plus the following
    4 bytes: msg_len uint32_t
    msg_len bytes: message char*
    4 bytes: arg_len uint32_t
    arg_len bytes: arg char*

NamespaceCerfiticate: BaseMessage, plus the follow
    4 bytes: id_len uint32_t
    id_len bytes: id char*
    4 bytes: desc_len uint32_t
    desc_len bytes: description char*
    4 bytes: addr_len uint32_t
    addr_len bytes: address char*
    4 bytes: port_len uint32_t
    port_len bytes: port char*
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
        virtual int Encode(char* const buf, const uint32_t buf_len) const;

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
        virtual int EncodedLength() const;

        // EncodeString
        // Given a string, encodes and saves it in to buf (of length buf_len) as 4 bytes length then the string itself
        // args
        //      [IN/OUT] buf: The buffer to which to save
        //      [IN] buf_len: the length of the buffer (to avoid overflow)
        //      [IN] str: The string we want to encode
        // return
        //      int: the number of bytes encoded and saved to buf, else a negative error code
        static int EncodeString(char* const buf, const uint32_t buf_len, const std::string& str);

        // EncodeBytes
        // Give a buffer, raw bytes, and a length for both, this encodes as 4 bytes unsigned length then the bytes themselves
        // args
        //      [IN/OUT] buf: The buffer to which to save
        //      [IN] buf_len: The length of the buffer
        //      [IN] bytes: The bytes to encode
        //      [IN] bytes_len: The number of bytes to encode
        // return
        //      int: the number of bytes encoded and saved to buf, else a negative error code
        static int EncodeBytes(char* const buf, const uint32_t buf_len, const char* const bytes, const uint32_t bytes_len);

        // DecodeString
        // Given a buffer of raw bytes, a length for that buffer, and a string object, decodes from the above functions
        // args
        //      [IN] buf: The raw bytes
        //      [IN] buf_len: The number of raw bytes
        //      [IN/OUT] str: The string object to which to save
        // return
        //      int: the number of bytes decoded
        static int DecodeString(const char* const buf, const uint32_t buf_len, std::string& str);
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

        virtual int Encode(char* const buf, const uint32_t buf_len) const override;
        virtual int Decode(const char* const buf, const uint32_t buf_len) override;
        virtual int EncodedLength() const override;
    };

    struct NamespaceCertificate : BaseMessage
    {
        std::string id;
        std::string description;
        std::string address;
        std::string port;

        NamespaceCertificate();

        virtual int Encode(char* const buf, const uint32_t buf_len) const override;
        virtual int Decode(const char* const buf, const uint32_t buf_len) override;
        virtual int EncodedLength() const override;
    };

    struct AccessControlList : BaseMessage
    {
        //std::vector<std::string> rules;

        AccessControlList();

        //virtual int Encode override (char* const buf, const uint32_t buf_len);
        //virtual int Decode override (const char* const buf, const uint32_t buf_len);
    };
}

#endif
