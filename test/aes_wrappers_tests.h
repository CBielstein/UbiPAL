// Cameron Bielstein, 2/15/15
// aes_wrappers_tests.h
// Holds unit tests for AesWrappers class for UbiPAL

#ifndef UBIPAL_TEST_AES_WRAPPERS_TESTS_H
#define UBIPAL_TEST_AES_WRAPPERS_TESTS_H

namespace UbiPAL
{
    // AesWrapperTests
    // Unit tests for the code in UbiPAL/src/aes_wrappers.h and UbiPAL/src/aes_wrappers.cpp
    class AesWrappersTests
    {
        private:
            // Unit tests
            static int AesWrappersTestsCreateKeyIv();
            static int AesWrappersTestsAesObjectsEqual();
            static int AesWrappersTestsAesObjectsStrings();
            static int AesWrappersTestsEncryptDecrypt();

            // End unit tests
        public:
            // Envoke all unit tests in this class
            static void RunAesWrappersTests(unsigned int& module_count, unsigned int& module_fails);
    };
}
#endif
