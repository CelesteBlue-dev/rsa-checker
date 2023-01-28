#include "rsa.h"


int verify_rsa_signature_with_pubkey_text(const char *sig, const char *pubkey, const char *exponent) {
	mpz_t n, e, pt, ct;
	// plaintext (signature)
	mpz_init_set_str(pt, sig, 16);
	mpz_init(ct);
	//modulus
	mpz_init_set_str(n, pubkey, 16);
	//exponent
	mpz_init_set_str(e, exponent, 16);
	//reverse exponent
	//mpz_init_set_str(d, "4DF6969D5F58B452", 16);
	if (mpz_cmp(pt, n) > 0)
		return -2;
	mpz_powm(ct, pt, e, n);
	//gmp_printf("Encoded:   %Zd\n", ct);
	/*
	mpz_powm(pt, ct, d, n);
	gmp_printf("Decoded:   %Zd\n", pt);
	*/
	char buffer[256];
	mpz_export(buffer, NULL, 1, 1, 0, 0, ct);
	mpz_clears(pt, ct, n, e, NULL);
	return !memcmp(&buffer, (char [4]){0x01, 0xFF, 0xFF, 0xFF}, 4);
}

int verify_message_with_rsa_signature_and_pubkey_text(const char *message, const char *sig, const char *pubkey, const char *exponent) {
	mpz_t n, e, pt, ct;
	mpz_init_set_str(pt, sig, 16);
	mpz_init(ct);
	//modulus
	mpz_init_set_str(n, pubkey, 16);
	//exponent
	mpz_init_set_str(e, exponent, 16);
	//reverse exponent
	//mpz_init_set_str(d, "4DF6969D5F58B452", 16);
	if (mpz_cmp(pt, n) > 0)
		return -2;
	mpz_powm(ct, pt, e, n);
	//gmp_printf("Encoded:   %Zd\n", ct);
	/*
	mpz_powm(pt, ct, d, n);
	gmp_printf("Decoded:   %Zd\n", pt);
	*/
	char buffer[256];
	mpz_export(buffer, NULL, 1, 1, 0, 0, ct);
	mpz_clears(pt, ct, n, e, NULL);
	FILE *fp = fopen("rsa_dec.bin", "wb+");
	fwrite(buffer, 1, 256, fp);
	if (memcmp(&buffer, (char [4]){0x01, 0xFF, 0xFF, 0xFF}, 4))
		return -1;
	return !(!memcmp(buffer+0xDF, message, 0x20));
}

int verify_rsa_signature_with_pubkey(const char *sig, const char *pubkey, int pubkey_len, const char *exponent) {
	mpz_t n, e, pt, ct;
	mpz_init(pt);
	mpz_import(pt, pubkey_len, 1, 1, 0, 0, sig);
	mpz_init(ct);
	mpz_init(n);
	mpz_import(n, pubkey_len, 1, 1, 0, 0, pubkey);
	mpz_init_set_str(e, exponent, 16);
	if (mpz_cmp(pt, n) > 0)
		return -2;
	mpz_powm(ct, pt, e, n);
	char buffer[256];
	mpz_export(buffer, NULL, 1, 1, 0, 0, ct);
	mpz_clears(pt, ct, n, e, NULL);
	return !memcmp(&buffer, (char [4]){0x01, 0xFF, 0xFF, 0xFF}, 4);
}

int verify_message_with_rsa_signature_and_pubkey(const char *message, const char *sig, const char *pubkey, int pubkey_len, const char *exponent) {
	mpz_t n, e, pt, ct;
	mpz_init(pt);
	mpz_import(pt, pubkey_len, 1, 1, 0, 0, sig);
	mpz_init(ct);
	mpz_init(n);
	mpz_import(n, pubkey_len, 1, 1, 0, 0, pubkey);
	mpz_init_set_str(e, exponent, 16);
	if (mpz_cmp(pt, n) > 0)
		return -2;
	mpz_powm(ct, pt, e, n);
	char buffer[256];
	mpz_export(buffer, NULL, 1, 1, 0, 0, ct);
	mpz_clears(pt, ct, n, e, NULL);
	if (memcmp(&buffer, (char [4]){0x01, 0xFF, 0xFF, 0xFF}, 4))
		return -1;
	return !(!memcmp(buffer+0xDF, message, 0x20));
}