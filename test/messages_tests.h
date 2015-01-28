// Cameron Bielstein, 1/27/15
// messages_tests.h
// Unit tests for messages.h & messages.cpp for UbiPAL

#ifndef UBIPAL_TEST_MESSAGES_TESTS_H
#define UBIPAL_TEST_MESSAGES_TESTS_H

namespace UbiPAL
{
    // ErrorTests
    // Unit tests for the code in UbiPAL/src/error.h and UbiPAL/src/error.cpp
    class MessagesTests
    {
        private:
            // Unit tests
            static int MessagesTestBaseMessageEncodeDecode();
            static int MessagesTestMessageEncodeDecode();
            static int MessagesTestMessageDefaultConstructor();
            static int MessagesTestMessageConstructor();

            // End Unit tests

        public:
            // Envoke all unit tests in this class
            static void RunMessagesTests(unsigned int& module_count, unsigned int& module_fails);
    };
}
#endif
