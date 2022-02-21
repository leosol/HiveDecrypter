/*
 ============================================================================
 Name        : HiveDecrypter.c
 Author      : leosol@gmail.com
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

unsigned char *KEY;
long KEY_LEN;
unsigned char FILE_HEAD[4096];
unsigned char FILE_TAIL[4096];
unsigned char *ABKEYS;
int ABKEYS_LEN;
int A_KEY = 0;
int B_KEY = 0;
unsigned char *MAGIC;
unsigned char *MAGIC_ENC;
int MAGIC_LEN;
unsigned long INDEX_KEY1 = 0;
unsigned long INDEX_KEY2 = 0;

void decrypt_small_file(char *encFile, char *decFile) {
	FILE *fileIn;
	long fileInLen;

	FILE *fileOut;

	unsigned char *bufferIn;
	unsigned char *bufferOut;

	fileIn = fopen(encFile, "rb");
	fseek(fileIn, 0, SEEK_END);
	fileInLen = ftell(fileIn);

	bufferIn = malloc(fileInLen * sizeof(char));
	bufferOut = malloc(fileInLen * sizeof(char));

	rewind(fileIn);
	fseek(fileIn, 0, SEEK_SET);
	fread(bufferIn, fileInLen, 1, fileIn);
	unsigned long tmpKey1 = INDEX_KEY1;
	unsigned long tmpKey2 = INDEX_KEY2;
	for (int i = 0; i < fileInLen; i++) {
		int isStart = i < 4096;
		int isEnd = (fileInLen > 4096 * 2) && i > (fileInLen - 4096);
		if (isStart || isEnd) {
			unsigned char key1;
			unsigned char key2;
			unsigned char cipher;
			unsigned char plain;
			key1 = KEY[tmpKey1];
			key2 = KEY[tmpKey2];
			cipher = bufferIn[i];
			plain = key1 ^ key2 ^ cipher;
			bufferOut[i] = plain;
			tmpKey1++;
			tmpKey2++;
			if(i>4096){
				tmpKey1 = INDEX_KEY1;
				tmpKey2 = INDEX_KEY2;
			}
		} else {
			bufferOut[i] = bufferIn[i];
		}
	}
	fileOut = fopen(decFile, "wb");
	fwrite(bufferOut, fileInLen, 1, fileOut);
	fclose(fileIn);
	fclose(fileOut);
}

void decrypt_block(unsigned char *bufferIn, unsigned char *bufferOut, int len) {
	unsigned char key1;
	unsigned char key2;
	unsigned char cipher;
	unsigned char plain;
	for (int i = 0; i < len; i++) {
		key1 = KEY[INDEX_KEY1];
		key2 = KEY[INDEX_KEY2];
		cipher = bufferIn[i];
		plain = key1 ^ key2 ^ cipher;
		bufferOut[i] = plain;
		INDEX_KEY1++;
		INDEX_KEY2++;
		if (INDEX_KEY1 >= KEY_LEN) {
			INDEX_KEY1 = 0;
		}
		if (INDEX_KEY2 >= KEY_LEN) {
			INDEX_KEY2 = 0;
		}
	}
}

void check_magic() {
	unsigned char key1;
	unsigned char key2;
	unsigned char cipher;
	unsigned char temp;
	unsigned char plain;
	unsigned long tmpKey1 = INDEX_KEY1;
	unsigned long tmpKey2 = INDEX_KEY2;
	int qtdMatch = 0;
	for (unsigned long i = 0; i < MAGIC_LEN; i++) {
		key1 = KEY[tmpKey1];
		key2 = KEY[tmpKey2];
		cipher = MAGIC_ENC[i];
		plain = MAGIC[i];
		temp = key1 ^ key2 ^ cipher;
		if (temp == plain) {
			qtdMatch++;
		}
		tmpKey1++;
		tmpKey2++;
		if (tmpKey1 >= KEY_LEN) {
			tmpKey1 = 0;
		}
		if (tmpKey2 >= KEY_LEN) {
			tmpKey2 = 0;
		}
	}
	if (qtdMatch == MAGIC_LEN) {
		printf("Success checking magic\n");
	} else {
		printf("Failed to check magic, resulted only %d matches in %d\n",
				qtdMatch, MAGIC_LEN);
	}

}

void parse_hex(char *label, char *hexStr, unsigned char **destBuffer,
		int *destBufferLen) {
	int magicHexStrLen = strlen(hexStr);
	int N = magicHexStrLen / 2;
	char *hexstring;
	hexstring = hexStr;
	char *pos = hexstring;
	unsigned char *val = malloc(N * sizeof(char));
	for (size_t count = 0; count < N; count++) {
		sscanf(pos, "%2hhx", &val[count]);
		pos += 2;
	}
	printf("%s: 0x", label);
	for (size_t count = 0; count < N; count++)
		printf("%02x", val[count]);
	printf("\n");
	*destBufferLen = N;
	*destBuffer = val;
}

void read_magic_enc(char *encFile) {
	if (MAGIC_LEN > 0) {
		MAGIC_ENC = malloc(MAGIC_LEN * sizeof(char));
		FILE *filePtr;
		filePtr = fopen(encFile, "rb");
		fseek(filePtr, 0, SEEK_SET);
		fread(MAGIC_ENC, MAGIC_LEN, 1, filePtr);
		fclose(filePtr);
	}
}

void read_key(char *keyFile) {
	FILE *filePtr;
	unsigned char *buffer;
	long filePtrlen;

	filePtr = fopen(keyFile, "rb");
	fseek(filePtr, 0, SEEK_END);
	filePtrlen = ftell(filePtr);
	rewind(filePtr);

	buffer = (unsigned char*) malloc(filePtrlen * sizeof(char));
	fread(buffer, filePtrlen, 1, filePtr);
	fclose(filePtr);
	KEY = buffer;
	KEY_LEN = filePtrlen;
}

void parse_abkeys() {
	unsigned int *ARRAY = (unsigned int*) ABKEYS;
	unsigned long key1 = (unsigned long) ARRAY[0];
	unsigned long key2 = (unsigned long) ARRAY[1];
	printf("Key1: %08lx\n", key1);
	printf("Key2: %08lx\n", key2);
	unsigned long tmp1 = (key1 >> 1) * 0x8DDA5203;
	tmp1 = tmp1 >> 50;
	tmp1 = tmp1 * 0xE7000;
	tmp1 = key1 - tmp1;
	printf("AKey index: %lx\n", tmp1);

	unsigned long tmp2 = (key2 >> 1) * 0x80604837;
	tmp2 = tmp2 >> 50;
	tmp2 = tmp2 * 0xFF400;
	tmp2 = key2 - tmp2;
	printf("BKey index: %lx\n", tmp2);
	INDEX_KEY1 = tmp1;
	INDEX_KEY2 = tmp2;
}

int main(int argc, char **argv) {
	char *keyFile;
	char *abKeys;
	char *encFile;
	char *decFile;
	char *magic;
	if (argc < 5) {
		printf("Usage: ");
		printf("HiveDecrypter <key> <ABkeys> <EncFile> <DecFile> <Magic>\n");
		printf("key:\t\ta file with 1048576 bytes (XOR keys)\n");
		printf(
				"ABkeys:\t\tLast few bytes found in the name of file. It must be base64 decoded.\n");
		printf("\t\tExample: \n");
		printf(
				"\t\tFor this encrypted file: E:\\AAAAAAAAA.txt.1NrjOhB9jpAPeZDMvcvTe3M0P5s_KSuHABl5xURqkwL_LbNZMAZv7fA0.8b5lc.\n");
		printf(
				"\t\t1NrjOhB9jpAPeZDMvcvTe3M0P5s_KSuHABl5xURqkwL is the encrypted key\n");
		printf("\t\tAnd the last LbNZMAZv7fA0 corresponds to AB Keys\n");
		printf(
				"\t\t$echo \"LbNZMAZv7fA0\"|base64 -d | od -A n -t x1|tr -d ' '\n");
		printf("\t\toutputs 2db35930066fedf034\n");
		printf(
				"\t\tThis sequence of bytes (2db35930066fedf034) has 2 decimal numbers that are used as double xor keys\n");
		printf("\t\tNote that the UNDESCORE should be replaced by slash \\\n");
		printf("EncFile:\t\tencripted file\n");
		printf("DecFile:\t\tnew decrypted file\n");
		printf(
				"Magic:\t\tOptional. First few bytes that are present in the begining of the file.\n");
		printf("\nEXAMPLE: \n");
		printf(
				"HiveDecrypter key 2db35930066fedf034 enc-file.txt dec-file.txt\n");
		return EXIT_SUCCESS;
	}
	keyFile = argv[1];
	abKeys = argv[2];
	encFile = argv[3];
	decFile = argv[4];
	if (argc > 5) {
		magic = argv[5];
	} else {
		magic = "";
	}
	printf("Arguments\n");
	printf("keyFile: %s\n", keyFile);
	printf("ABkeys: %s\n", abKeys);
	printf("EncFile: %s\n", encFile);
	printf("DecFile: %s\n", decFile);
	printf("Magic: %s\n", magic);

	read_key(keyFile);
	parse_hex("ABkeys", abKeys, &ABKEYS, &ABKEYS_LEN);
	parse_hex("Magic", magic, &MAGIC, &MAGIC_LEN);
	read_magic_enc(encFile);
	if (ABKEYS_LEN != 9) {
		printf("ABKEYS should have exactly 9 bytes\n");
		printf("Found %d bytes. Seems wrong... quiting...\n", ABKEYS_LEN);
		return EXIT_SUCCESS;
	}
	parse_abkeys();
	if (MAGIC_LEN > 0) {
		check_magic();
	}
	decrypt_small_file(encFile, decFile);
	printf("File was decrypted and saved to %s\n", decFile);
	return EXIT_SUCCESS;
}
