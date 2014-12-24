// Cameron Bielstein, 12/23/14
// tests.cpp
// Tests for UbiPAL

#include "rsa_wrapper_tests.cpp"
#include "test_helpers.cpp"

int main()
{
    unsigned int fail_count = 0;
    unsigned int total_count = 0;

    // Run tests
    run_test_module(rsa_wrapper_tests, "rsa_wrapper_tests", total_count, fail_count);

    // Results
    fprintf(stderr, "%d tests run, %d failures.\n", total_count, fail_count);
    if (fail_count == 0)
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
