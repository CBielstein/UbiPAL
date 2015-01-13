// Cameron Bielstein, 1/2/15
// error_tests.h
// Unit tests for error.h & error.cpp for UbiPAL

#ifndef UBIPAL_TEST_LOG_TESTS_H
#define UBIPAL_TEST_LOG_TESTS_H

namespace UbiPAL
{
    // LogTests
    // Unit tests for the code in UbiPAL/src/log.h and UbiPAL/src/log.cpp
    class LogTests
    {
        private:
            // Unit tests
            static int LogTestIsValidLevelTrue();
            static int LogTestIsValidLevelFalse();
            static int LogTestSetPrintTrue();
            static int LogTestSetPrintFalse();
            static int LogTestSetLevelValid();
            static int LogTestSetLevelInvalid();
            static int LogTestSetLogFile();
            static int LogTestSetLogFileEmpty();
            static int LogTestConfigureAllEmpty();
            static int LogTestConfigureFilePointerEmpty();
            static int LogTestConfigureFileNameEmpty();
            static int LogTestLine();
            static int LogTestLineConfigure();
            static int LogTestLineNull();

            static int LogTestFlush();
            static int LogTestFlushNull();

            // End Unit tests

        public:
            // Envoke all unit tests in this class
            static void RunLogTests(unsigned int& module_count, unsigned int& module_fails);
    };
}

#endif
