#include "libpwparser.h"

void usage(char* bin) {
	fprintf(stderr,"Usage: %s FILE\n",bin);
	fprintf(stderr,"Example: %s /etc/passwd\n",bin);
}

typedef struct _bash_users {
	char* username;
	struct _bash_users* next;
} bash_users;

static bash_users* bash_users_head = NULL;
static bash_users* bash_users_current = NULL;

void add_bash_user(tList* node) {
	if(!bash_users_head) {
		bash_users_head = malloc(sizeof(bash_users));
		memset(bash_users_head,0,sizeof(bash_users));
		bash_users_current = bash_users_head;
		bash_users_current->username = strdup(node->username);
		bash_users_current->next = NULL;
		return;
	}
	bash_users* new_node = malloc(sizeof(bash_users));
	new_node->username = strdup(node->username);
	new_node->next = NULL;
	bash_users_current->next = new_node;
	bash_users_current = new_node;
}

void cleanup_bash_users() {
	bash_users* ptr = bash_users_head;
	while(ptr) {
		printf("Free'ing bash user: '%s'\n",ptr->username);
		free(ptr->username);
		bash_users* tmp = ptr->next;
		free(ptr);
		ptr = tmp;
	}
}

int my_row_filter(tList* node) {
	if(strcmp(node->shell,"/bin/bash") == 0) {
		add_bash_user(node);
	}
	return CB_KEEP_ITERATING;
}

void cleanup_all(parser_context* ctx,char* dupd_string) {
	free(dupd_string);
	pwp_close(ctx);
	cleanup_bash_users();
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
	row_callback r = my_row_filter;

	ctx->row_cb = &r;
	int parse_status = pwp_parse(ctx,&filter);
	if(parse_status != PARSE_OK) {
		fprintf(
		    stderr,
		    "Failed to parse contents: %d ('%s')\n",
		    ctx->error,
		    pwp_strerror(ctx->error)
		);
		cleanup_all(ctx,filter.data);
		return 3;
	}

	cleanup_all(ctx,filter.data);
	return EXIT_SUCCESS;
}
