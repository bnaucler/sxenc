#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FEXT ".ap"
#define KEYFILE ".sxkey"

#define CHARSET "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

#define KEYLEN 512
#define FNLEN 128
#define MBCH 1024

#define M_ENCRYPT 0
#define M_DECRYPT 1
#define M_GENKEY 2

typedef struct flag {
	int mfl;
	int vfl;
} flag;

int die(char *err, int ret) {

	if(err[0]) fprintf(stderr, "Error: %s\n", err);

	exit(ret);
}

char *crypt(char *dst, const char *src, const char *key, size_t sz) {

	const char *kptr = key, *sptr = src;
	unsigned int a = 0;

	for(a = 0; a < sz; a++) {
		if(!kptr) kptr = key;
		*dst++ = *sptr++ ^ *kptr++;
	}

	*dst = 0;

	return dst;
}

char *getkey(char *key, int klen) {

	char fname[FNLEN];
	snprintf(fname, FNLEN, "%s%c%s", getenv("HOME"), '/', KEYFILE);

	FILE *fp = fopen(fname, "r");
	if(!fp) die("Could not open key file (run with -g (size) to generate)", 4);

	fread(key, 1, klen, fp);

	return key;
}

int encloop(FILE *src, FILE *dst, char *key, flag *f) {

	char *buf = calloc(MBCH, sizeof(char));
	char *enc = calloc(MBCH, sizeof(char));

	size_t len = 0;

	while((len = fread(buf, 1, MBCH, src))) {
		crypt(enc, buf, key, len);
		if(f->mfl == M_ENCRYPT) fwrite(enc, 1, len, dst);
		else printf("%s", enc);
	}

	free(buf);
	free(enc);
	return 0;
}

int execop(flag *f, char **argv) {

	FILE *src, *dst;

	char *key = calloc(KEYLEN + 1, sizeof(char));
	getkey(key, KEYLEN);

	do {
		src = fopen(*argv, "r");
		if(!src) return die("Cannot open file", 2);

		if(f->mfl == M_DECRYPT) {
			encloop(src, NULL, key, f);

		} else {
			strncat(*argv, FEXT, FNLEN); // hack

			dst = fopen(*argv, "w");
			if(!dst) return die("Cannot create encrypted file", 3);

			encloop(src, dst, key, f);

			fclose(dst);
		}

		fclose(src);

	} while(*++argv);

	free(key);
	return 0;
}

int keygen(flag *f, char **argv) {

	time_t t;
	srand((unsigned) time(&t));

	unsigned int a = 0;

    int klen = (int) strtol(*argv, NULL, 10);
	if(klen > KEYLEN || klen < 10) klen = KEYLEN;

	char key[(KEYLEN + 1)];
	int cslen = strlen(CHARSET);

	for(a = 0; a < klen; a++) key[a] = CHARSET[(rand() % cslen)];

	char fname[FNLEN];
	snprintf(fname, FNLEN, "%s%c%s", getenv("HOME"), '/', KEYFILE);

	FILE *fp = fopen(fname, "w");
	if(!fp) die("Could not write to key file", 3);

	fwrite(key, 1, strlen(key) + 1, fp);

	return 0;
}

void setfl(char *arg, flag *f) {

	while(*++arg) {
		switch(*arg) {

			case 'd':
				f->mfl = M_DECRYPT;
				break;

			case 'g':
				f->mfl = M_GENKEY;
				break;

			case 'v':
				f->vfl++;
				break;
		}
	}
}

int main(int argc, char **argv) {

	int ret = 0;

	flag *f = calloc(1, sizeof(flag));

	if(argc < 2 || (argc == 2 && argv[1][0] == '-'))
		die("Not enough arguments", 1);
	else if (argv[1][0] == '-') setfl(argv++[1], f);

	if(f->mfl == M_GENKEY) ret =  keygen(f, ++argv);
	else ret = execop(f, ++argv);

	free(f);
	return ret;
}
