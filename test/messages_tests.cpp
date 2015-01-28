// Cameron Bielstein, 1/2/15
// error_tests.cpp
// Unit tests for error.h & error.cpp for UbiPAL

// tested code
#include "../src/messages.h"

// test code
#include "messages_tests.h"
#include "test_helpers.h"

// ubipal
#include "../src/error.h"

// standard
#include <string>
#include <string.h>

namespace UbiPAL
{
    int MessagesTests::MessagesTestBaseMessageEncodeDecode()
    {
        int status = SUCCESS;
        BaseMessage bm;
        BaseMessage bm2;
        char msg[MAX_MESSAGE_SIZE];

        bm.type = MESSAGE;
        bm.to = std::string("robert");
        bm.from = std::string("cameron");

        status = bm.Encode(msg, MAX_MESSAGE_SIZE);
        if (status < 0)
        {
            return status;
        }

        status = bm2.Decode(msg, MAX_MESSAGE_SIZE);
        if (status < 0)
        {
            return status;
        }

        if (bm.type != bm2.type || bm.to.compare(bm2.to) != 0 || bm.from.compare(bm2.from) != 0)
        {
            fprintf(stderr, "Failed comparison. types: %d == %d, to: %s == %s, from: %s == %s\n",
                    bm.type, bm2.type, bm.to.c_str(), bm2.to.c_str(), bm.from.c_str(), bm.from.c_str());
            return GENERAL_FAILURE;
        }

        return SUCCESS;
    }

    int MessagesTests::MessagesTestMessageEncodeDecode()
    {
        int status = SUCCESS;
        const char* m_arg = "please";
        Message m(m_arg, strlen(m_arg));
        Message m2;
        char msg[MAX_MESSAGE_SIZE];

        m.to = std::string("robert");
        m.from = std::string("cameron");
        m.message = std::string("door_open");

        status = m.Encode(msg, MAX_MESSAGE_SIZE);
        if (status < 0)
        {
            return status;
        }

        status = m2.Decode(msg, MAX_MESSAGE_SIZE);
        if (status < 0)
        {
            return status;
        }

        if (m.type != m2.type || m.to.compare(m2.to) != 0 || m.from.compare(m2.from) != 0 ||
            m.message.compare(m2.message) != 0 || m.arg_len != m2.arg_len || memcmp(m.argument, m2.argument, m.arg_len) != 0)
        {
            fprintf(stderr, "Failed comparison. types: %d == %d, to: %s == %s, from: %s == %s, message: %s == %s, arg_len: %u == %u, argument: %s == %s\n",
                    m.type, m2.type, m.to.c_str(), m2.to.c_str(), m.from.c_str(), m.from.c_str(), m.message.c_str(), m2.message.c_str(), m.arg_len, m2.arg_len, m.argument, m2.argument);
            return GENERAL_FAILURE;
        }

        return SUCCESS;
    }

    int MessagesTests::MessagesTestMessageDefaultConstructor()
    {
        int status = SUCCESS;
        Message m;

        if (m.type != MESSAGE)
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    int MessagesTests::MessagesTestMessageConstructor()
    {
        int status = SUCCESS;
        const char* test = "I gotta say it was a good day.";
        Message m(test, strlen(test));

        if (m.type != MESSAGE || m.arg_len != strlen(test) || memcmp(test, m.argument, m.arg_len) != 0)
        {
            return GENERAL_FAILURE;
        }

        return status;
    }

    void MessagesTests::RunMessagesTests(unsigned int& module_count, unsigned int& module_fails)
    {
        TestHelpers::RunTestFunc(MessagesTestBaseMessageEncodeDecode, SUCCESS,
                                 "MessagesTestBaseMessageEncodeDecode", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestMessageEncodeDecode, SUCCESS,
                                 "MessagesTestMessageEncodeDecode", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestMessageDefaultConstructor, SUCCESS,
                                 "MessagesTestMessageDefaultConstructor", module_count, module_fails);
        TestHelpers::RunTestFunc(MessagesTestMessageConstructor, SUCCESS,
                                 "MessagesTestMessageConstructor", module_count, module_fails);
    }
}
