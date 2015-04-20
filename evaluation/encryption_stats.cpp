// Cameron Bielstein, 4/12/15
// encryption_stats.cpp
// Runs encryption tests for UbiPAL evaluation

#include <iostream> // cout
#include <stdlib.h> // atoi
#include <string.h> // memcmp
#include <ubipal/error.h>
#include <ubipal/rsa_wrappers.h>
#include <ubipal/aes_wrappers.h>

#define EVALUATE

#ifdef EVALUATE
    extern uint32_t NUM_RSA_ENCRYPTS;
    extern double TIME_RSA_ENCRYPTS;
    extern uint32_t NUM_RSA_DECRYPTS;
    extern double TIME_RSA_DECRYPTS;
    extern uint32_t NUM_RSA_SIGNS;
    extern double TIME_RSA_SIGNS;
    extern uint32_t NUM_RSA_VERIFIES;
    extern double TIME_RSA_VERIFIES;
    extern uint32_t NUM_RSA_GENERATES;
    extern double TIME_RSA_GENERATES;
    extern uint32_t NUM_AES_ENCRYPTS;
    extern double TIME_AES_ENCRYPTS;
    extern uint32_t NUM_AES_DECRYPTS;
    extern double TIME_AES_DECRYPTS;
    extern uint32_t NUM_AES_GENERATES;
    extern double TIME_AES_GENERATES;
#endif

int main(int argc, char** argv)
{
    int status = UbiPAL::SUCCESS;
    int num_reps = 0;
    RSA* rsa_key = nullptr;
    RSA* public_key = nullptr;
    unsigned char* encrypted_test_string = nullptr;
    unsigned int encrypted_test_string_len = 0;
    unsigned char* result_test_string = nullptr;
    unsigned int result_test_string_len = 0;
    unsigned char* signature = nullptr;
    unsigned int signature_len = 0;
    unsigned char* aes_key = nullptr;
    unsigned char* aes_iv = nullptr;

    // random characters from randomcharacters.com
    const unsigned char* test_string = (const unsigned char*)"cpmofqgrymeotscpwptvbqkqlbsxhfvvtpmlltkmvtphbwmglpthspmxnfaodsvalbwfmnhcnkmufvburydmtjgngpjrviiagvqm";
    const unsigned int test_string_len = 100;

    // Take number of reps as input
    if (argc != 2)
    {
        std::cout << "Usage: encryption_stats [num_reps]" << std::endl;
        goto exit;
    }
    num_reps = atoi(argv[1]);

    // initialize variables
    NUM_RSA_ENCRYPTS = 0;
    TIME_RSA_ENCRYPTS = 0.0;
    NUM_RSA_DECRYPTS = 0;
    TIME_RSA_DECRYPTS = 0.0;
    NUM_RSA_SIGNS = 0;
    TIME_RSA_SIGNS = 0.0;
    NUM_RSA_VERIFIES = 0;
    TIME_RSA_VERIFIES = 0.0;
    NUM_RSA_GENERATES = 0;
    TIME_RSA_GENERATES = 0.0;
    NUM_AES_ENCRYPTS = 0;
    TIME_AES_ENCRYPTS = 0.0;
    NUM_AES_DECRYPTS = 0;
    TIME_AES_DECRYPTS = 0.0;
    NUM_AES_GENERATES = 0;
    TIME_AES_GENERATES = 0.0;

    // Then run that number of...

    // RSA generate
    for (int i = 0; i < num_reps; ++i)
    {
        status = UbiPAL::RsaWrappers::GenerateRsaKey(rsa_key);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failure in RSA generate: " << UbiPAL::GetErrorDescription(status) << std::endl;
            goto exit;
        }

        // if this is the last rep, save the key for future tests
        if (i != num_reps - 1)
        {
            RSA_free(rsa_key);
        }
    }

    // RSA encrypts & decrypts

    status = UbiPAL::RsaWrappers::CreatePublicKey(rsa_key, public_key);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failure in CreatePublicKey: " << UbiPAL::GetErrorDescription(status) << std::endl;
        goto exit;
    }
    // encrypt public, decrypt private. This is the normal method used in UbiPAL
    for (int i = 0; i < num_reps; ++i)
    {
        status = UbiPAL::RsaWrappers::Encrypt(public_key, test_string, test_string_len, encrypted_test_string, &encrypted_test_string_len);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failure in RSA Encrypt: " << UbiPAL::GetErrorDescription(status) << std::endl;
            goto exit;
        }

        status = UbiPAL::RsaWrappers::Decrypt(rsa_key, encrypted_test_string, encrypted_test_string_len, result_test_string, &result_test_string_len);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failure in RSA Decrypt: " << UbiPAL::GetErrorDescription(status) << std::endl;
            goto exit;
        }

        if (test_string_len != result_test_string_len || memcmp(test_string, result_test_string, test_string_len) != 0)
        {
            std::cout << "Result did not match source for RSA encrypt/decrypt" << std::endl;
            status = UbiPAL::GENERAL_FAILURE;
            goto exit;
        }

        free(encrypted_test_string);
        free(result_test_string);
        encrypted_test_string = nullptr;
        result_test_string = nullptr;
    }

    // RSA signs & verifies
    for (int i = 0; i < num_reps; ++i)
    {
        status = UbiPAL::RsaWrappers::CreateSignedDigest(rsa_key, test_string, test_string_len, signature, signature_len);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failure in RSA Sign: " << UbiPAL::GetErrorDescription(status) << std::endl;
            goto exit;
        }

        status = UbiPAL::RsaWrappers::VerifySignedDigest(public_key, test_string, test_string_len, signature, signature_len);
        if (status != 1)
        {
            status = (status == UbiPAL::SUCCESS) ? UbiPAL::GENERAL_FAILURE : status;
            std::cout << "Failure in RSA Verify " << UbiPAL::GetErrorDescription(status) << std::endl;
            goto exit;
        }

        free(signature);
        signature = nullptr;
    }

    // AES Generates
    for (int i = 0; i < num_reps - 2; ++i)
    {
        status = UbiPAL::AesWrappers::GenerateAesObject(aes_key, NULL);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failure in AES Generate " << UbiPAL::GetErrorDescription(status) << std::endl;
            goto exit;
        }

        free(aes_key);
        aes_key = nullptr;
    }

    status = UbiPAL::AesWrappers::GenerateAesObject(aes_key, NULL);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failure in AES Generate " << UbiPAL::GetErrorDescription(status) << std::endl;
        goto exit;
    }
    status = UbiPAL::AesWrappers::GenerateAesObject(aes_iv, NULL);
    if (status != UbiPAL::SUCCESS)
    {
        std::cout << "Failure in AES Generate " << UbiPAL::GetErrorDescription(status) << std::endl;
        goto exit;
    }

    // AES encrypts & decrypts
    for (int i = 0; i < num_reps; ++i)
    {
        status = UbiPAL::AesWrappers::Encrypt(aes_key, aes_iv, test_string, test_string_len, encrypted_test_string, &encrypted_test_string_len);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failure in AES Encrypt: " << UbiPAL::GetErrorDescription(status) << std::endl;
            goto exit;
        }

        status = UbiPAL::AesWrappers::Decrypt(aes_key, aes_iv, encrypted_test_string, encrypted_test_string_len, result_test_string, &result_test_string_len);
        if (status != UbiPAL::SUCCESS)
        {
            std::cout << "Failure in AES Decrypt: " << UbiPAL::GetErrorDescription(status) << std::endl;
            goto exit;
        }

        if (test_string_len != result_test_string_len || memcmp(test_string, result_test_string, test_string_len) != 0)
        {
            std::cout << "Result did not match source for AES encrypt/decrypt" << std::endl;
            status = UbiPAL::GENERAL_FAILURE;
            goto exit;
        }

        free(encrypted_test_string);
        free(result_test_string);
        encrypted_test_string = nullptr;
        result_test_string = nullptr;
    }

    exit:
        // free memory
        RSA_free(rsa_key);
        RSA_free(public_key);
        free(encrypted_test_string);
        free(result_test_string);
        free(signature);
        free(aes_key);
        free(aes_iv);

        // print results
        std::cout << "After " << num_reps << " repetitions..." << std::endl;
        std::cout << NUM_RSA_ENCRYPTS << " RSA encrypts: " << TIME_RSA_ENCRYPTS << " total, " <<  TIME_RSA_ENCRYPTS/NUM_RSA_ENCRYPTS << " average." << std::endl;
        std::cout << NUM_RSA_DECRYPTS << " RSA decrypts: " << TIME_RSA_DECRYPTS << " total, " <<  TIME_RSA_DECRYPTS/NUM_RSA_DECRYPTS << " average." << std::endl;
        std::cout << NUM_RSA_SIGNS << " RSA signs: " << TIME_RSA_SIGNS << " total, " <<  TIME_RSA_SIGNS/NUM_RSA_SIGNS << " average." << std::endl;
        std::cout << NUM_RSA_VERIFIES << " RSA verifies: " << TIME_RSA_VERIFIES << " total, " <<  TIME_RSA_VERIFIES/NUM_RSA_VERIFIES << " average." << std::endl;
        std::cout << NUM_RSA_GENERATES << " RSA generates: " << TIME_RSA_GENERATES << " total, " <<  TIME_RSA_GENERATES/NUM_RSA_GENERATES << " average." << std::endl;
        std::cout << NUM_AES_ENCRYPTS << " AES encrypts: " << TIME_AES_ENCRYPTS << " total, " <<  TIME_AES_ENCRYPTS/NUM_AES_ENCRYPTS << " average." << std::endl;
        std::cout << NUM_AES_DECRYPTS << " AES decrypts: " << TIME_AES_DECRYPTS << " total, " <<  TIME_AES_DECRYPTS/NUM_AES_DECRYPTS << " average." << std::endl;
        std::cout << NUM_AES_GENERATES << " AES generates: " << TIME_AES_GENERATES << " total, " <<  TIME_AES_GENERATES/NUM_AES_GENERATES << " average." << std::endl;

        // return
        return status;
}
