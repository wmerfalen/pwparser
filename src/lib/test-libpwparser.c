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
	parser_context* ctx = pwp_create();
	if(ctx->error != 0) {
		fprintf(stderr,"Failed to create context: %d ('%s')\n",ctx->error,pwp_strerror(ctx->error));
		return 2;
	}

	filter_expression filter;
	filter.target = T_COLUMN;
	filter.target_data = T_USERNAME;
	filter.operation = OP_STRING_COMPARE;
	filter.operation_data = NO_OPERATION_DATA;
	filter.data = strdup("root");

	int parse_status = pwp_parse(ctx,&filter);
	if(parse_status != PARSE_OK) {
		fprintf(
		    stderr,
		    "Failed to parse contents: %d ('%s')\n",
		    ctx->error,
		    pwp_strerror(ctx->error)
		);
		free(filter.data);
		pwp_close(ctx);
		return 3;
	}

	free(filter.data);
	pwp_close(ctx);

	return EXIT_SUCCESS;
}
