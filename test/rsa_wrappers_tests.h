// Cameron Bielstein, 1/1/15
// rsa_wrappers_tests.h
// Holds unit tests for RSA_wrappers class for UbiPAL

#ifndef UBIPAL_TEST_RSA_WRAPPERS_TESTS_H
#define UBIPAL_TEST_RSA_WRAPPERS_TESTS_H

namespace UbiPAL
{
    // RsaWrapperTests
    // Unit tests for the code in UbiPAL/src/rsa_wrappers.h and UbiPAL/src/rsa_wrappers.cpp
    class RsaWrappersTests
    {
        private:
            // Unit tests

            static int RsaWrappersGenerateKey();
            // signed by private, verified by public
            static int RsaWrappersBasic();
            // signed by private, failed verification by wrong public key
            static int RsaWrappersWrongPubKey();
            // signed by private, failed verification by wrong private key
            static int RsaWrappersWrongPrivKey();
            static int RsaWrappersIsPrivateTrue();
            static int RsaWrappersIsPrivateFalse();
            // encrypt public, decrypt private
            static int RsaWrappersEncryptDecryptBasic();
            // encrypt private, decrypt public
            static int RsaWrappersEncryptDecryptBasicReverse();
            // encrypt public, decrypt wrong private and fail
            static int RsaWrappersEncryptDecryptWrongKey();
            // encrypt private, decrypt wrong public and fail
            static int RsaWrappersEncryptDecryptWrongKeyReverse();
            // encrypt private, decrypt public
            static int RsaWrappersEncryptDecryptPublicFail();
            static int RsaWrappersCopyKeyPrivate();
            static int RsaWrappersCopyKeyPublic();
            static int RsaWrappersKeysEqualTrueSameKey();
            static int RsaWrappersKeysEqualTruePrivate();
            static int RsaWrappersKeysEqualFalsePrivate();
            static int RsaWrappersKeysEqualTruePublic();
            static int RsaWrappersKeysEqualFalsePublic();
            static int RsaWrappersKeysEqualFalsePublicPrivate();

            // End unit tests
        public:
            // Envoke all unit tests in this class
            static void RunRsaWrappersTests(unsigned int& module_count, unsigned int& module_fails);
    };
}
#endif
