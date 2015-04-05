// Cameron Bielstein, 1/20/15
// ubipal_service_tests.h
// Unit tests for error.h & error.cpp for UbiPAL

#ifndef UBIPAL_TEST_UBIPAL_SERVICE_TESTS_H
#define UBIPAL_TEST_UBIPAL_SERVICE_TESTS_H

namespace UbiPAL
{
    // ErrorTests
    // Unit tests for the code in UbiPAL/src/error.h and UbiPAL/src/error.cpp
    class UbipalServiceTests
    {
        private:
            // Unit tests
            static int UbipalServiceTestDefaultConstructor();
            static int UbipalServiceTestConstructor();
            static int UbipalServiceTestConstructorNullNonnull();
            static int UbipalServiceTestConstructorNonnullNull();
            static int UbipalServiceTestEndRecv();
            static int UbipalServiceTestSetAddress();
            static int UbipalServiceTestSetPort();
            static int UbipalServiceTestSetDescription();
            static int UbipalServiceTestRegisterCallback();
            static int UbipalServiceTestRegisterCallbackUpdate();
            static int UbipalServiceTestSaveReadFile();
            static int UbipalServiceTestConditionParse();
            static int UbipalServiceTestParseTimeDate();
            static int UbipalServiceTestDiscoverService();
            static int UbipalServiceTestParseDelegation();
            static int UbipalServiceTestParseDelegationVariable();
            static int UbipalServiceTestParseDelegationVariableConditions();
            static int UbipalServiceTestParseBoundedDelegation();
            static int UbipalServiceTestUpperCase();

            // End Unit tests

        public:
            // Envoke all unit tests in this class
            static void RunUbipalServiceTests(unsigned int& module_count, unsigned int& module_fails);
    };
}
#endif
