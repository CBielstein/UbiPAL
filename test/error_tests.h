// Cameron Bielstein, 1/2/15
// error_tests.h
// Unit tests for error.h & error.cpp for UbiPAL

#ifndef ERROR_TESTS_H
#define ERROR_TESTS_H

#include "test_helpers.h"
#include "../src/error.h"
#include <cstring>

namespace UbiPAL
{
    class error_tests
    {
        private:
            // Unit tests
            static int error_test_return_success();
            static int error_test_string_success();
            static int error_test_string_invalid();

            // End Unit tests

        public:
            // Envoke all unit tests in this class
            static void run_error_tests(unsigned int& module_count, unsigned int& module_fails);
    };
}
#endif
