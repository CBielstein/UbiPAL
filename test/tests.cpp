// Cameron Bielstein, 12/23/14
// tests.cpp
// Tests for UbiPAL

#include "test_helpers.h"
#include "../src/log.h"

// Test classes
#include "rsa_wrappers_tests.h"
#include "error_tests.h"
#include "log_tests.h"
#include "ubipal_service_tests.h"

// Capture log output, but print to stderr for most messages in case the log is failing
// this test log may be helpful however, so we'll keep it around
inline void SetLogDetails()
{
    UbiPAL::Log::SetLevel(UbiPAL::Log::DEBUG);
    UbiPAL::Log::SetPrint(false);
    UbiPAL::Log::SetFile("bin/test/log.txt");
}

int main()
{
    unsigned int overall_fail_count = 0;
    unsigned int overall_test_count = 0;
    unsigned int module_count = 0;
    unsigned int failed_modules = 0;

    SetLogDetails();
    UbiPAL::Log::Line(UbiPAL::Log::INFO, "BEGIN UNIT TESTS: There are some expected failures and the log may behave strangely during log unit tests.");

    // Run tests
    TestHelpers::RunTestModule(UbiPAL::RsaWrappersTests::RunRsaWrappersTests, "RsaWrapperTests",
                               overall_test_count, overall_fail_count,
                               module_count, failed_modules);
    TestHelpers::RunTestModule(UbiPAL::ErrorTests::RunErrorTests, "ErrorTests",
                               overall_test_count, overall_fail_count,
                               module_count, failed_modules);
    TestHelpers::RunTestModule(UbiPAL::LogTests::RunLogTests, "LogTests",
                               overall_test_count, overall_fail_count,
                               module_count, failed_modules);
    // Reset log after log unit tests
    SetLogDetails();
    TestHelpers::RunTestModule(UbiPAL::UbipalServiceTests::RunUbipalServiceTests, "UbipalServiceTests",
                               overall_test_count, overall_fail_count,
                               module_count, failed_modules);

    // End tests
    UbiPAL::Log::Line(UbiPAL::Log::INFO, "END UNIT TESTS.");
    UbiPAL::Log::FlushLog();

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
