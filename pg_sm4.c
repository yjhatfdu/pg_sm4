#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "postgres.h"
#include "executor/executor.h"
PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(sm4_cbc_encrypt);
PG_FUNCTION_INFO_V1(sm4_cbc_decrypt);
char *handleErrors(EVP_CIPHER_CTX *ctx);
int encryptData(char *plaintext, int plaintext_len, const char *key,
                const char *iv, char *ciphertext, char **error);
int decryptData(char *ciphertext, int ciphertext_len, const char *key,
                const char *iv, char *plaintext, char **error);

char *handleErrors(EVP_CIPHER_CTX *ctx)
{
    char *error;
    // ERR_print_errors_fp(stderr);
    error = ERR_error_string(ERR_get_error(), NULL);
    EVP_CIPHER_CTX_cleanup(ctx);
    return error;
}

int encryptData(char *plaintext, int plaintext_len, const char *key,
                const char *iv, char *ciphertext, char **error)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        *error = handleErrors(ctx);
        return -1;
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */

    if (1 != EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, (const unsigned char *)(key), (const unsigned char *)(iv)))
    {
        *error = handleErrors(ctx);
        return -1;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)(ciphertext), &len, (unsigned char *)(plaintext), plaintext_len))
    {
        *error = handleErrors(ctx);
        return -1;
    }
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)(ciphertext + len), &len))
    {
        *error = handleErrors(ctx);
        return -1;
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// function decryptData
int decryptData(char *ciphertext, int ciphertext_len, const char *key,
                const char *iv, char *plaintext, char **error)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        *error = handleErrors(ctx);
        return -1;
    }

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, (const unsigned char *)(key), (const unsigned char *)(iv)))
    {
        *error = handleErrors(ctx);
        return -1;
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, (unsigned char *)(plaintext), &len, (unsigned char *)(ciphertext), ciphertext_len))
    {
        *error = handleErrors(ctx);
        return -1;
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char *)(plaintext + len), &len))
    {
        *error = handleErrors(ctx);
        return -1;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

Datum sm4_cbc_encrypt(PG_FUNCTION_ARGS)
{
    bytea *plaintext = PG_GETARG_BYTEA_P(0);
    bytea *key = PG_GETARG_BYTEA_P(1);
    bytea *iv = PG_GETARG_BYTEA_P(2);
    bytea *ciphertext;
    int ciphertext_len;
    char **error = NULL;
    if (VARSIZE_ANY_EXHDR(key) != 16)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("sm4_cbc_decrypt error: key length must be 16, but %lu", VARSIZE_ANY_EXHDR(key))));
        return 0;
    }

    if (VARSIZE_ANY_EXHDR(iv) != 16)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("sm4_cbc_decrypt error: iv length must be 16, but %lu", VARSIZE_ANY_EXHDR(iv))));
        return 0;
    }
    ciphertext = (bytea *)palloc((VARSIZE_ANY_EXHDR(plaintext) / 16 + 1) * 16 + VARHDRSZ);
    SET_VARSIZE(ciphertext, VARSIZE_ANY_EXHDR(plaintext) + VARHDRSZ);
    ciphertext_len = encryptData(VARDATA(plaintext), VARSIZE_ANY_EXHDR(plaintext), VARDATA(key), VARDATA(iv), VARDATA(ciphertext), error);
    if (error != NULL)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("sm4_cbc_encrypt error: %s", *error)));
        free(*error);
        return 0;
    }
    SET_VARSIZE(ciphertext, ciphertext_len + VARHDRSZ);
    PG_RETURN_BYTEA_P(ciphertext);
}

Datum sm4_cbc_decrypt(PG_FUNCTION_ARGS)
{
    bytea *ciphertext = PG_GETARG_BYTEA_P(0);
    bytea *key = PG_GETARG_BYTEA_P(1);
    bytea *iv = PG_GETARG_BYTEA_P(2);
    bytea *plaintext;
    int plaintext_len;
    char **error = NULL;
    if (VARSIZE_ANY_EXHDR(ciphertext) % 16 != 0)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("sm4_cbc_decrypt error: ciphertext length must be multiple of 16")));
        return 0;
    }
    if (VARSIZE_ANY_EXHDR(key) != 16)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("sm4_cbc_decrypt error: key length must be 16")));
        return 0;
    }
    if (VARSIZE_ANY_EXHDR(iv) != 16)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("sm4_cbc_decrypt error: iv length must be 16")));
        return 0;
    }
    plaintext = (bytea *)palloc(VARSIZE_ANY_EXHDR(ciphertext) + VARHDRSZ);
    SET_VARSIZE(plaintext, VARSIZE_ANY_EXHDR(ciphertext) + VARHDRSZ);
    plaintext_len = decryptData(VARDATA(ciphertext), VARSIZE_ANY_EXHDR(ciphertext), VARDATA(key), VARDATA(iv), VARDATA(plaintext), error);
    if (error != NULL)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("sm4_cbc_decrypt error: %s", *error)));
        free(*error);
        return 0;
    }
    SET_VARSIZE(plaintext, plaintext_len + VARHDRSZ);
    PG_RETURN_BYTEA_P(plaintext);
}