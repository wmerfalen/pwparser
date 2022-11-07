#include "libpwparser.h"

void usage(char* bin) {
	fprintf(stderr,"Usage: %s FILE\n",bin);
	fprintf(stderr,"Example: %s /etc/passwd\n",bin);
}

int main(int argc, char** argv) {
	if(argc < 2) {
		usage(argv[0]);
		return 1;
	}
	parser_context* ctx = pwp_create(argv[1]);

	return EXIT_SUCCESS;
}

#endif
