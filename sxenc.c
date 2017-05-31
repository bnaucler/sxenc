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

char *crypt(char *str, const char *key, size_t sz) {

	char *sptr = str;
	const char *kptr = key;
	size_t a = 0;

	for(a = 0; a < sz; a++) {
		if(!kptr) kptr = key;
		*sptr = *sptr ^ *kptr++;
		sptr++;
	}

	return str;
}

char *kfname(char *str) {

	snprintf(str, FNLEN, "%s%c%s", getenv("HOME"), '/', KEYFILE);

	return str;
}

char *getkey(char *key, int klen) {

	char fname[FNLEN];

	FILE *fp = fopen(kfname(fname), "r");
	if(!fp) die("Could not open key file (run with -g (size) to generate)", 4);

	fread(key, 1, klen, fp);

	fclose(fp);
	return key;
}

int encloop(FILE *src, FILE *dst, char *key, flag *f) {

	char buf[MBCH];
	size_t len = 0;

	while((len = fread(buf, 1, MBCH, src))) {
		crypt(buf, key, len);
		if(f->mfl == M_ENCRYPT) fwrite(buf, 1, len, dst);
		else printf("%s", buf);
	}

	return 0;
}

int execop(flag *f, char **argv) {

	char key[(KEYLEN + 1)];
	getkey(key, KEYLEN);

	do {
		FILE *src = fopen(*argv, "r");
		if(!src) die("Cannot open file", 2);

		if(f->mfl == M_DECRYPT) {
			encloop(src, NULL, key, f);

		} else {
			strncat(*argv, FEXT, FNLEN); // hack

			FILE *dst = fopen(*argv, "w");
			if(!dst) die("Cannot create encrypted file", 3);

			encloop(src, dst, key, f);

			fclose(dst);
		}

		fclose(src);

	} while(*++argv);

	return 0;
}

int keygen(flag *f, char **argv) {

	time_t t;
	srand((unsigned int) time(&t));

	char fname[FNLEN];
	int cslen = strlen(CHARSET);
	unsigned int a = 0;

	int klen = (int) strtol(*argv, NULL, 10);
	if(klen > KEYLEN || klen < 10) klen = KEYLEN;

	FILE *fp = fopen(kfname(fname), "w");
	if(!fp) die("Could not write to key file", 3);

	for(a = 0; a < klen; a++) fputc(CHARSET[(rand() % cslen)], fp);

	fclose(fp);
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

	flag f;

	if(argc < 2 || (argc == 2 && argv[1][0] == '-'))
		die("Not enough arguments", 1);
	else if (argv[1][0] == '-') setfl(argv++[1], &f);

	if(f.mfl == M_GENKEY) return keygen(&f, ++argv);
	else return execop(&f, ++argv);
}
