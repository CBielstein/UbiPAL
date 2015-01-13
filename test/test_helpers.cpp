// Cameron Bielstein, 12/23/14
// test_helpers.cpp
// Helper functions for UbiPAL test framework

#include "test_helpers.h"
#include <cstdio>

int TestHelpers::RunTestFunc(const TestFunction func, const int nominal, const char* name,
                             unsigned int& total_count, unsigned int& fail_count)
{
    int status = UbiPAL::SUCCESS;

    status = func();
    if (status != nominal)
    {
        fprintf(stderr, "    \033[31m%s failed with status %d\n\033[0m", name, status);
        ++fail_count;
    }
    else
    {
        fprintf(stderr, "    \033[32m%s succeeded\n\033[0m", name);
    }

    ++total_count;
    return status;
}

void TestHelpers::RunTestModule(const TestModule module, const char* name,
                                unsigned int& overall_test_count, unsigned int& overall_fail_count,
                                unsigned int& module_count, unsigned int& failed_modules)
{
    unsigned int module_test_count = 0;
    unsigned int module_fail_count = 0;

    fprintf(stderr, "Begin module %s:\n", name);

    module(module_test_count, module_fail_count);
    if (module_fail_count > 0)
    {
        fprintf(stderr, "\033[31mModule %s had failures: %d tests run, %d failures\n\033[0m", name, module_test_count, module_fail_count);
        ++failed_modules;
    }
    else
    {
        fprintf(stderr, "\033[32mModule %s had no failures: %d tests run, %d failures\n\033[0m", name, module_test_count, module_fail_count);
    }

    overall_fail_count += module_fail_count;
    overall_test_count += module_test_count;
    ++module_count;
}
