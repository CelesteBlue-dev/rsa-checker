#include <stdio.h>
#include <string.h>
#include <gmp.h>


int verify_rsa_signature_with_pubkey_text(const char *sig, const char *pubkey, const char *exponent);
int verify_message_with_rsa_signature_and_pubkey_text(const char *message, const char *sig, const char *pubkey, const char *exponent);
int verify_rsa_signature_with_pubkey(const char *sig, const char *pubkey, int pubkey_len, const char *exponent);
int verify_message_with_rsa_signature_and_pubkey(const char *message, const char *sig, const char *pubkey, int pubkey_len, const char *exponent);