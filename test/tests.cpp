// Cameron Bielstein, 12/23/14
// tests.cpp
// Tests for UbiPAL

#include "test_helpers.h"

// Test classes
#include "RSA_wrappers_tests.h"
#include "error_tests.h"

int main()
{
    unsigned int overall_fail_count = 0;
    unsigned int overall_test_count = 0;
    unsigned int module_count = 0;
    unsigned int failed_modules = 0;

    // Run tests
    Test_Helpers::run_test_module(UbiPAL::RSA_wrappers_tests::run_rsa_wrappers_tests, "rsa_wrapper_tests",
                                  overall_test_count, overall_fail_count,
                                  module_count, failed_modules);
    Test_Helpers::run_test_module(UbiPAL::error_tests::run_error_tests, "error_tests",
                                  overall_test_count, overall_fail_count,
                                  module_count, failed_modules);

    // Results
    fprintf(stderr, "%d modules run, %d modules had failures\n%d tests run, %d failures.\n",
            module_count, failed_modules, overall_test_count, overall_fail_count);
    if (overall_fail_count == 0 && failed_modules == 0)
    {
        fprintf(stderr, "\033[32mAll tests pass.\n\033[0m");
        return EXIT_SUCCESS;
    }
    else
    {
        fprintf(stderr, "\033[31mTests had failures!\n\033[0m");
        return EXIT_FAILURE;
    }
}
