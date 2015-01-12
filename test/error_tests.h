// Cameron Bielstein, 1/2/15
// error_tests.h
// Unit tests for error.h & error.cpp for UbiPAL

#ifndef UBIPAL_TEST_ERROR_TESTS_H
#define UBIPAL_TEST_ERROR_TESTS_H

#include "test_helpers.h"
#include "../src/error.h"
#include <cstring>

namespace UbiPAL
{
    // ErrorTests
    // Unit tests for the code in UbiPAL/src/error.h and UbiPAL/src/error.cpp
    class ErrorTests
    {
        private:
            // Unit tests
            static int ErrorTestReturnSuccess();
            static int ErrorTestStringSuccess();
            static int ErrorTestStringInvalid();

            // End Unit tests

        public:
            // Envoke all unit tests in this class
            static void RunErrorTests(unsigned int& module_count, unsigned int& module_fails);
    };
}
#endif
