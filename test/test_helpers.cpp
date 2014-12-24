// Cameron Bielstein, 12/23/14
// test_helpers.cpp
// Helper functions for UbiPAL test framework

#ifndef TEST_HELPERS_CPP
#define TEST_HELPERS_CPP

typedef int(*test_function)(void);
int run_test_func(const test_function func, const int nominal, const char* name,
             unsigned int& total_count, unsigned int& fail_count)
{
    int status = EXIT_SUCCESS;

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

typedef void(*test_module)(unsigned int&, unsigned int&);
void run_test_module(const test_module module, const char* name,
                    unsigned int& overall_total_count, unsigned int& overall_fail_count)
{
    unsigned int module_count = 0;
    unsigned int module_fails = 0;

    fprintf(stderr, "Begin module %s:\n", name);

    module(module_count, module_fails);
    if (module_fails > 0)
    {
        fprintf(stderr, "\033[31mModule %s had failures: %d tests run, %d failures\n\033[0m", name, module_count, module_fails);
    }
    else
    {
        fprintf(stderr, "\033[32mModule %s had no failures: %d tests run, %d failures\n\033[0m", name, module_count, module_fails);
    }

    overall_fail_count += module_fails;
    overall_total_count += module_count;
}

#endif
