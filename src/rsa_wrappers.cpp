// Cameron Bielstein, 12/23/14
// rsa_wrappers.cpp
// Wrapper functions for OpenSSL's RSA encryption and verification algorithms


#include "rsa_wrappers.h"

int RSA_wrappers::generate_rsa_key(RSA*& rsa)
{
    int status = EXIT_SUCCESS;

    // we're creating a NEW key at rsa
    rsa = RSA_new();

    // set e = 3, that seems to work fine
    BIGNUM* e = BN_new();
    status = BN_add(e, BN_value_one(), BN_value_one());
    if (status != 1) { fprintf(stderr, "Failed on BN_add in generate_rsa_key\n"); return EXIT_FAILURE; }
    status = BN_add(e, e, BN_value_one());
    if (status != 1) { fprintf(stderr, "Failed on BN_add in generate_rsa_key\n"); return EXIT_FAILURE; }

    // seed time
    srand(time(NULL));

    // generate key
    status = RSA_generate_key_ex(rsa, 1024, e, NULL);
    if (status < 0 )
    {
        fprintf(stderr, "RSA_generate_key_ex failed. Returned %d, %s\n", status, ERR_error_string(ERR_get_error(), NULL));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int RSA_wrappers::create_public_key(const RSA* priv_key, RSA*& pub_key)
{
    if (priv_key == nullptr)
    {
        fprintf(stderr, "Passed a null argument in create_public_key(%p, %p)\n", priv_key, pub_key);
        return EXIT_FAILURE;
    }

    // we're creating a NEW key at pub_key
    pub_key = RSA_new();

    // copy over public elements
    pub_key->n = BN_dup(priv_key->n);
    pub_key->e = BN_dup(priv_key->e);

    return EXIT_SUCCESS;
}

int RSA_wrappers::create_signed_digest(RSA* priv_key, const unsigned char* msg,
                                       const unsigned int msg_length, unsigned char*& sig,
                                       unsigned int& sig_len)
{
    int status = EXIT_SUCCESS;

    if (priv_key == NULL || msg == NULL)
    {
        fprintf(stderr, "NULL args: create_signed_digest(%p, %p, %u, %p, %d)\n", priv_key, msg, msg_length, sig, sig_len);
        return EXIT_FAILURE;
    }

    // hash the message
    unsigned char* digest = SHA1((unsigned char*)msg, msg_length, NULL);
    if (digest == NULL)
    {
        fprintf(stderr, "SHA1 failed in create_signed_digest. Returned NULL\n");
        return EXIT_FAILURE;
    }

    // sign that digest!
    sig = (unsigned char*)malloc(RSA_size(priv_key));
    status = RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sig, &sig_len, priv_key);
    if (status != 1)
    {
        fprintf(stderr, "RSA_sign failed in create_signed_digest. Returned %d, %s\n", status, ERR_error_string(ERR_get_error(), NULL));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

bool RSA_wrappers::verify_signed_digest(RSA* pub_key, const unsigned char* msg,
                                       const unsigned int msg_length, const unsigned char* sig,
                                       const unsigned int sig_len)
{
    unsigned char* digest = SHA1((unsigned char*)msg, msg_length, NULL);
    if (digest == NULL)
    {
        fprintf(stderr, "SHA1 failed in create_signed_digest. Returned NULL\n");
        return EXIT_FAILURE;
    }

    int verified = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, (unsigned char *)sig, sig_len, pub_key);

    return (verified == 1);
}
