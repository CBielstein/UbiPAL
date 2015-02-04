// Cameron Bielstein, 1/27/15
// messages_tests.h
// Unit tests for messages.h & messages.cpp for UbiPAL

#ifndef UBIPAL_TEST_MESSAGES_TESTS_H
#define UBIPAL_TEST_MESSAGES_TESTS_H

// Used for a static buffer length in the MessagesTestBaseMessageEncodeUint32_tDecodeUint32_t function
#define UINT32_T_TEST_BUF_LEN 9

namespace UbiPAL
{
    // ErrorTests
    // Unit tests for the code in UbiPAL/src/error.h and UbiPAL/src/error.cpp
    class MessagesTests
    {
        private:
            // Unit tests
            static int MessagesTestBaseMessageDefaultConstructor();
            static int MessagesTestBaseMessageEncodeStringDecodeString();
            static int MessagesTestBaseMessageEncodeUint32_tDecodeUint32_t();
            static int MessagesTestBaseMessageEncodeDecode();
            static int MessagesTestMessageEncodeDecode();
            static int MessagesTestNamespaceCertificateEncodeDecode();
            static int MessagesTestMessageDefaultConstructor();
            static int MessagesTestMessageConstructor();
            static int MessagesTestAccessControlListEncodeDecode();
            static int MessagesTestAccessControlListDefaultConstructor();

            // End Unit tests

        public:
            // Envoke all unit tests in this class
            static void RunMessagesTests(unsigned int& module_count, unsigned int& module_fails);
    };
}
#endif
