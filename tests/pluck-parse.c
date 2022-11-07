#include "libpwparser.h"

void usage(char* bin) {
	fprintf(stderr,"Usage: %s FILE\n",bin);
	fprintf(stderr,"Example: %s /etc/passwd\n",bin);
}

int my_pluck_callback(int col, char* ptr, unsigned int* i_ptr) {
	if(col == T_USERNAME) {
		printf("Plucked username: '%s'\n",ptr);
	} else if(col == T_HOME) {
		printf("Plucked home directory: '%s'\n",ptr);
	} else if(col == T_SHELL) {
		printf("Plucked shell: '%s'\n",ptr);
	} else {
		printf("Plucked???\n");
	}

	return CB_KEEP_ITERATING;
}
int example_pluck(char* file) {
	parser_context* ctx = pwp_create_from(file);
	if(ctx->error != 0) {
		fprintf(stderr,"Failed to create context: %d ('%s')\n",ctx->error,pwp_strerror(ctx->error));
		return 2;
	}
	column_callback c = my_pluck_callback;

	int parse_status = pwp_pluck_column(ctx,(T_USERNAME | T_HOME | T_SHELL), &c);
	if(parse_status != PARSE_OK) {
		fprintf(
		    stderr,
		    "Failed to parse contents: %d ('%s')\n",
		    ctx->error,
		    pwp_strerror(ctx->error)
		);
		pwp_close(ctx);
		return 3;
	}

	pwp_close(ctx);
	return EXIT_SUCCESS;
}
int main(int argc, char** argv) {
	if(argc < 2) {
		usage(argv[0]);
		return 1;
	}

	int epluck = example_pluck(argv[1]);
	printf("epluck result: %d\n",epluck);

	return 0;
}
