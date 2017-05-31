#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENCKEY "this is the key"
#define FEXT ".ap"

#define FNLEN 128
#define MBCH 1024

#define M_ENCRYPT 0
#define M_DECRYPT 1

typedef struct flag {
	int mfl;
	int vfl;
} flag;

int die(char *err, int ret) {

	if(err[0]) fprintf(stderr, "Error: %s\n", err);

	return ret;
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

	do {
		src = fopen(*argv, "r");
		if(!src) return die("Cannot open file", 2);

		if(f->mfl == M_DECRYPT) {
			encloop(src, NULL, ENCKEY, f);

		} else {
			strncat(*argv, FEXT, FNLEN); // hack

			dst = fopen(*argv, "w");
			if(!dst) return die("Cannot create encrypted file", 3);

			encloop(src, dst, ENCKEY, f);

			fclose(dst);
		}

		fclose(src);

	} while(*++argv);

	return 0;
}

void setfl(char *arg, flag *f) {

	while(*++arg) {
		switch(*arg) {

			case 'd':
				f->mfl = M_DECRYPT;
				break;

			case 'v':
				f->vfl++;
				break;
		}
	}
}

int main(int argc, char **argv) {

	flag *f = calloc(1, sizeof(flag));

	if(argc < 2 || (argc == 2 && argv[1][0] == '-'))
		return die("No file specified", 1);
	else if (argv[1][0] == '-') setfl(argv++[1], f);

	return execop(f, ++argv);
}
