#include <stdio.h>
#include <string.h>

#include "rsa.h"


char pubkey[256] = {0xBB, 0x1E, 0x13, 0x96, 0x36, 0x48, 0xB5, 0xEC, 0x36, 0xEC, 0x4D, 0xDD, 0x00, 0xDD, 0x37, 0x52, 0x53, 0xB4, 0x7A, 0x3F, 0xD4, 0x52, 0xBB, 0x67, 0xF1, 0xFB, 0x8B, 0x09, 0x67, 0xDD, 0xAB, 0x08, 0xAA, 0x82, 0x45, 0x62, 0x00, 0xCC, 0x90, 0x06, 0xD2, 0x7D, 0xD0, 0x01, 0x44, 0xF3, 0x6C, 0x5C, 0x98, 0xEF, 0x4A, 0x2C, 0x53, 0x07, 0x4C, 0x65, 0x49, 0x78, 0xF4, 0x9A, 0xE8, 0x2E, 0x25, 0x89, 0x88, 0x7E, 0x2D, 0xF2, 0x4E, 0x74, 0x8B, 0xDB, 0x1B, 0x2E, 0xE2, 0x22, 0xF8, 0xC6, 0xEC, 0x6E, 0x0D, 0xF3, 0xC3, 0x26, 0x66, 0x20, 0x98, 0x82, 0xC0, 0x08, 0xD6, 0x6A, 0xEE, 0x35, 0xF1, 0x8F, 0xD8, 0xA8, 0x10, 0xB8, 0x86, 0xB1, 0xA9, 0x26, 0xC3, 0xC9, 0x69, 0x06, 0x48, 0x2F, 0xAB, 0x7B, 0x10, 0x3E, 0xF7, 0x69, 0x00, 0xFE, 0x7C, 0x1D, 0xF1, 0x30, 0x41, 0x05, 0x13, 0x98, 0xCA, 0xE8, 0x83, 0xB8, 0x48, 0x50, 0x69, 0xF9, 0x8C, 0xB7, 0x8C, 0xD2, 0x75, 0xC9, 0x67, 0x14, 0xDB, 0x22, 0xC9, 0x1C, 0xF1, 0x9B, 0x4B, 0xE2, 0xC7, 0x7A, 0xC2, 0x28, 0xC9, 0x3D, 0xFA, 0x0B, 0x09, 0xDA, 0xAD, 0xE4, 0xAC, 0xFD, 0xA2, 0x6D, 0x66, 0xDF, 0xFD, 0x18, 0xDD, 0xE5, 0x88, 0x95, 0xA3, 0x4C, 0xA6, 0x37, 0x7C, 0x25, 0x94, 0x60, 0x3F, 0xE4, 0x1E, 0x0C, 0x50, 0x62, 0x15, 0x07, 0x61, 0xD8, 0x73, 0xFB, 0x53, 0x94, 0xD1, 0x03, 0x2F, 0xC0, 0x92, 0x9F, 0x9E, 0xD6, 0xC5, 0xBE, 0x05, 0x1B, 0x03, 0x9C, 0x6C, 0x5B, 0xF5, 0xD9, 0x2B, 0xEB, 0xC3, 0xEC, 0x83, 0xEC, 0x06, 0xE3, 0xCC, 0x7B, 0x5E, 0xC1, 0xBC, 0xE4, 0x45, 0x62, 0x27, 0x41, 0xCD, 0x60, 0xBE, 0x2D, 0xDC, 0xF8, 0x38, 0x48, 0xBC, 0x86, 0xB3, 0xEB, 0xF9, 0x87, 0xC4, 0x38, 0x32, 0x0B, 0x6D, 0xEA, 0xD9, 0xD4, 0xEE, 0x27};
char* exponent = "10001";

int test_rsa_lib(void) {
	char message[32] = {0x0D, 0x92, 0x02, 0x74, 0x9D, 0x30, 0x25, 0x5E, 0xF1, 0xFD, 0xCC, 0x22, 0x64, 0x07, 0xF7, 0xD7, 0x4B, 0x48, 0x9A, 0x37, 0x0D, 0xC7, 0xBA, 0xC0, 0xB9, 0x3A, 0x2B, 0x35, 0x15, 0x5C, 0x0D, 0xCA};
	return verify_message_with_rsa_signature_and_pubkey_text(message
	, "7BF79EE56AB7E37B607054AB2F3A6E50CAD8702CAE5FA1154B648651CCAA20FC0B0B011132FACFF326305AF11A4E46D39854E9E4148A518DF6AAC422CE068DAA53B63FD0EDB0D8A2D5F770F20697C310C210FE897B355D574D880DE619C6D45D2EB11C3F71D4D567233D215443987D4608B36DE53BCD5A9542DDB1E79BFDD8F6787E15DED4784C3C425F221B244750077ECAE952C1B7F8F59CC84B648F772700785535CE8D65415F9E2417A29B4277A681631C098ED3AC179F45F6A5EDB7969BF212D69DD371F499896F821D42F00FCDFA1BB609B0428A15B0CD387456F65EED1C1EABC1CA1095BE4752E8EC672D5A4F7D73E14AAB2751E453B1B487C347C370"
	, "BB1E13963648B5EC36EC4DDD00DD375253B47A3FD452BB67F1FB8B0967DDAB08AA82456200CC9006D27DD00144F36C5C98EF4A2C53074C654978F49AE82E2589887E2DF24E748BDB1B2EE222F8C6EC6E0DF3C32666209882C008D66AEE35F18FD8A810B886B1A926C3C96906482FAB7B103EF76900FE7C1DF13041051398CAE883B8485069F98CB78CD275C96714DB22C91CF19B4BE2C77AC228C93DFA0B09DAADE4ACFDA26D66DFFD18DDE58895A34CA6377C2594603FE41E0C5062150761D873FB5394D1032FC0929F9ED6C5BE051B039C6C5BF5D92BEBC3EC83EC06E3CC7B5EC1BCE445622741CD60BE2DDCF83848BC86B3EBF987C438320B6DEAD9D4EE27"
	, "10001"
	);
}

int main(void) {
	unsigned int ret = -1;

	ret = test_rsa_lib();
	if (ret == 0)
		printf("RSA library working... Continuing\n");
	else {
		printf("RSA library not working... Aborting\n");
		return -1;
	}
	
	char message[0x20];
	memset(&message, 0x66, 0x20);
	FILE *fp = fopen("message.bin", "rb");
	if (fp == NULL)
		printf("Could not open message.bin!\n");
	ret = fread(&message, 1, 0x20, fp);
	if (ret != 0x20)
		printf("Invalid SHA-256 hash message!\n");

	char sig[256];
	memset(&sig, 0x66, 256);
	FILE *fp_sig = fopen("sig.bin", "rb");
	if (fp_sig == NULL)
		printf("Could not open sig.bin!\n");
	ret = fread(&sig, 1, 256, fp_sig);
	if (ret != 256)
		printf("Invalid signature!\n");
	ret = verify_message_with_rsa_signature_and_pubkey(message
	, sig
	, pubkey
	, sizeof(pubkey)
	, exponent
	);
	if (ret == 0)
		printf("Valid message according to RSA!");
	else if (ret == 1)
		printf("Invalid message according to RSA!");
	else if (ret == -1)
		printf("Invalid RSA signature or private key!\n");
	else
		printf("Unknown RSA error!\n");
	return 0;
}