// Cameron Bielstein, 1/27/15
// messages.cpp
// Message types and certificates for UbiPAL

// header
#include "messages.h"

// ubipal
#include "log.h"
#include "error.h"
#include "macros.h"

// standard
#include <arpa/inet.h>
#include <string.h>

namespace UbiPAL
{
    int BaseMessage::Decode(const char* const buf, const uint32_t buf_len)
    {
        FUNCTION_START;
        uint8_t* type_ptr = nullptr;
        uint32_t* len_ptr = nullptr;
        uint32_t length = 0;
        char* str_bits = nullptr;
        char* buff = nullptr;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "BaseMessage::Decode: Decode(%p, %u)", buf, buf_len);
            RETURN_STATUS(INVALID_ARG);
        }

        // cast of the constness of buff. It's const in the header to show it won't be changed,
        // but it needs to be non-const for later casts
        buff = const_cast<char*>(buf);
        if (buff == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::Decode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }

        // decode message type
        length = 1;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::Decode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        type_ptr = reinterpret_cast<uint8_t*>(buff);
        if (type_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::Decode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }
        type = *type_ptr;
        offset += length;

        // decode to length
        length = 4;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::Decode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        len_ptr = reinterpret_cast<uint32_t*>(buff + offset);
        if (len_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::Decode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }
        offset += length;
        length = ntohl(*len_ptr);

        // decode to
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::Decode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        str_bits = buff + offset;
        to = std::string(str_bits, length);
        offset += length;

        // decode from length
        length = 4;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::Decode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        len_ptr = reinterpret_cast<uint32_t*>(buff + offset);
        if (len_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::Decode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }
        offset += length;
        length = ntohl(*len_ptr);

        // decode from
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::Decode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        str_bits = buff + offset;
        from = std::string(str_bits, length);
        offset += length;

        status = offset;

        exit:
            FUNCTION_END;
    }

    int BaseMessage::Encode(char* const buf, const uint32_t buf_len)
    {
        FUNCTION_START;
        uint8_t* type_ptr = nullptr;
        uint32_t* len_ptr = nullptr;
        uint32_t length = 0;
        char* str_bits = nullptr;
        uint32_t offset = 0;
        uint32_t size = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: Encode(%p, %u)", buf, buf_len);
            RETURN_STATUS(INVALID_ARG);
        }

        // encode message type
        length = 1;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(INVALID_ARG);
        }
        type_ptr = reinterpret_cast<uint8_t*>(buf);
        if (type_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::Encode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }
        *type_ptr = type;
        offset += length;

        // encode to length
        length = 4;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        len_ptr = reinterpret_cast<uint32_t*>(buf + offset);
        if (len_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::Encode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }
        size = to.size();
        *len_ptr = htonl(size);
        offset += length;

        // encode to
        if (buf_len < offset + size)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        str_bits = buf + offset;
        strncpy(str_bits, to.c_str(), size);
        offset += size;

        // encode from length
        length = 4;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        len_ptr = reinterpret_cast<uint32_t*>(buf + offset);
        if (len_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "BaseMessage::Encode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }
        size = from.size();
        *len_ptr = htonl(size);
        offset += length;

        // encode from
        if (buf_len < offset + size)
        {
            Log::Line(Log::WARN, "BaseMessage::Encode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        str_bits = buf + offset;
        strncpy(str_bits, from.c_str(), size);
        offset += size;

        status = offset;

        exit:
            FUNCTION_END;
    }

    int BaseMessage::EncodedLength()
    {
        return 1 + 4 + to.size() + 4 + from.size();
    }

    int Message::Encode(char* const buf, const uint32_t buf_len)
    {
        FUNCTION_START;
        uint32_t* len_ptr = nullptr;
        uint32_t length = 0;
        char* str_bits = nullptr;
        uint32_t offset = 0;
        uint32_t size = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "Message::Encode: Decode(%p, %u)", buf, buf_len);
            RETURN_STATUS(INVALID_ARG);
        }

        // encode basemessage part of the struct
        status = BaseMessage::Encode(buf, buf_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "Message::Encode: BaseMessage::Encode failed: %s", GetErrorDescription(status));
            RETURN_STATUS(status);
        }
        else
        {
            offset = status;
        }

        // encode message length
        length = 4;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "Message::Encode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        len_ptr = reinterpret_cast<uint32_t*>(buf + offset);
        if (len_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Encode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }
        size = message.size();
        *len_ptr = htonl(size);
        offset += length;

        // encode message
        if (buf_len < offset + size)
        {
            Log::Line(Log::WARN, "Message::Encode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        str_bits = buf + offset;
        strncpy(str_bits, message.c_str(), size);
        offset += size;

        // encode arg length
        length = 4;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "Message::Encode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        len_ptr = reinterpret_cast<uint32_t*>(buf + offset);
        if (len_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Encode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }
        size = arg_len;
        *len_ptr = htonl(size);
        offset += length;

        // encode arg
        if (buf_len < offset + size)
        {
            Log::Line(Log::WARN, "Message::Encode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        str_bits = buf + offset;
        strncpy(str_bits, argument, size);
        offset += size;

        status = offset;

        exit:
            FUNCTION_END;
    }

    int Message::Decode(const char* const buf, const uint32_t buf_len)
    {
        FUNCTION_START;
        uint32_t* len_ptr = nullptr;
        uint32_t length = 0;
        char* str_bits = nullptr;
        char* buff = nullptr;
        uint32_t offset = 0;

        if (buf == nullptr || buf_len == 0)
        {
            Log::Line(Log::WARN, "BaseMessage::Decode: Decode(%p, %u)", buf, buf_len);
            RETURN_STATUS(INVALID_ARG);
        }

        // decode the basemessage part of the struct
        status = BaseMessage::Decode(buf, buf_len);
        if (status < 0)
        {
            Log::Line(Log::WARN, "Message::Decode: BaseMessage::Decode failed: %s", GetErrorDescription(status));
            RETURN_STATUS(status);
        }
        else
        {
            offset = status;
        }

        // cast of the constness of buff. It's const in the header to show it won't be changed,
        // but it needs to be non-const for later casts
        buff = const_cast<char*>(buf);
        if (buff == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Decode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }

        // decode message length
        length = 4;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "Message::Decode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        len_ptr = reinterpret_cast<uint32_t*>(buff + offset);
        if (len_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Decode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }
        offset += length;
        length = ntohl(*len_ptr);

        // decode to
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "Message::Decode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        str_bits = buff + offset;
        message = std::string(str_bits, length);
        offset += length;

        // decode args length
        length = 4;
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "Message::Decode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        len_ptr = reinterpret_cast<uint32_t*>(buff + offset);
        if (len_ptr == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Decode: reinterpet_cast failed.");
            RETURN_STATUS(GENERAL_FAILURE);
        }
        offset += length;
        length = ntohl(*len_ptr);
        arg_len = length;

        // decode args
        if (buf_len < offset + length)
        {
            Log::Line(Log::WARN, "Message::Decode: Given a buf too short: buf_len %u < offset %u + length %u", buf_len, offset, length);
            RETURN_STATUS(BUFFER_TOO_SMALL);
        }
        str_bits = buff + offset;
        argument = (char*)malloc(length);
        if (argument == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Decode: malloc failed");
            RETURN_STATUS(MALLOC_FAILURE);
        }
        memcpy(argument, str_bits, length);
        offset += length;

        status = offset;

        exit:
            FUNCTION_END;
    }

    int Message::EncodedLength()
    {
        return BaseMessage::EncodedLength() + 4 + message.size() + 4 + arg_len;
    }

    Message::Message()
    {
        type = MESSAGE;
        argument = nullptr;
    }

    Message::Message(const char* const arg, const uint32_t arg_size)
        : Message()
    {
        if (arg == nullptr || arg_size == 0)
        {
            return;
        }

        argument = (char*)malloc(arg_size);
        if (argument == nullptr)
        {
            Log::Line(Log::EMERG, "Message::Message: malloc failed.");
            arg_len = 0;
        }
        else
        {
            memcpy(argument, arg, arg_size);
            arg_len = arg_size;
        }
    }

    Message::~Message()
    {
        free(argument);
    }

    NamespaceCertificate::NamespaceCertificate()
    {
       type = NAMESPACE_CERTIFICATE;
    }

    AccessControlList::AccessControlList()
    {
        type = NAMESPACE_CERTIFICATE;
    }

}
