// Cameron Bielstein, 1/1/15
// test_helpers.h
// Helper functions for UbiPAL test framework

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include "../src/error.h"

typedef int(*test_function)(void);
typedef void(*test_module)(unsigned int&, unsigned int&);

// Test_Helpers
// A class to hold static functions for running tests and test modules
class Test_Helpers
{
    public:
        // run_test_func
        // Runs a single test function
        // args
        //      [IN] func: a test function to be run
        //      [IN] nominal: the expected successful return value
        //      [IN] name: a string name of the test being run
        //      [IN/OUT] total_count: keeps count of functions run
        //      [IN/OUT] fail_count: keeps track of failures
        // return
        //      returns the return value of the test
        static int run_test_func(const test_function func, const int nominal, const char* name,
                                 unsigned int& total_count, unsigned int& fail_count);

        // run_test_module
        // Runs a module of tests
        // args
        //      [IN] module: a module of tests to run, simple a function with many calls to run_test_func
        //      [IN] name: a string name of the module
        //      [IN/OUT] overall_test_count: tracking number of tests run across all modules
        //      [IN/OUT] overall_fail_count: tracking number of tests failed across all modules
        //      [IN/OUT] module_count: tracking number of modules run
        //      [IN/OUT] failed_modules: tracking number of failed modules
        static void run_test_module(const test_module module, const char* name,
                                    unsigned int& overall_test_count, unsigned int& overall_fail_count,
                                    unsigned int& module_count, unsigned int& failed_modules);
};

#endif
