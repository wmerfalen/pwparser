#ifndef __ETC_PASSWD_PARSER_LIB_HEADER__
#define __ETC_PASSWD_PARSER_LIB_HEADER__

// TODO REMOVE ME
#define DEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#define CTX_READ_SIZE(c) c->stats.st_size

enum errors {
	ERR_OPEN = 1,
	ERR_FSTAT,
	ERR_MMAP,
	ERR_USERNAME,
	ERR_COLON,
	ERR_PASSWORD,
	ERR_COLON_PASSWORD,
	ERR_UID,
	ERR_COLON_UID,
	ERR_GID,
	ERR_COLON_GID,
	ERR_GECOS,
	ERR_GECOS_COLON,
	ERR_HOMEDIR,
	ERR_COLON_HOMEDIR,
	ERR_SHELL,
	ERR_NEWLINE,
	ERR_OUT_OF_MEMORY,
};

typedef struct sList {
	char* username;
	char* password;
	char* gecos_uid;
	char* home;
	char* shell;
	unsigned int uid;
	unsigned int gid;
	struct sList* next;
} tList;

typedef struct _parser_context {
	const char* buf;
	off_t buf_index;
	const char* file_name;
	struct stat stats;
	int fd;
	size_t arena_index;
	size_t arena_size;
	void* arena;
	tList* users_list;
	tList* users_list_head;
	unsigned int line_number;
	int8_t premature_eof;
	int error;
} parser_context;


void init_arena(parser_context* ctx,size_t sz) {
	ctx->arena_size = sz;
	ctx->arena = malloc(ctx->arena_size);
}
void double_arena(parser_context* ctx) {
	ctx->arena_size *= 2;
	ctx->arena = realloc(ctx->arena,ctx->arena_size);
}
void dump();

void* pwp_malloc(parser_context* ctx,size_t s) {
	intptr_t base = (intptr_t)((char*)ctx->arena);
	if(base + s >= base + ctx->arena_size) {
		double_arena(ctx);
	}
	char* ptr = (char*)ctx->arena;
	ptr += ctx->arena_index;
	ctx->arena_index += s;
	/**
	 * TODO: change remove this optionally and see if alignment
	 * issues still pop up
	 */
	if(ctx->arena_index % 8 != 0) {
		ctx->arena_index += 8 - ctx->arena_index % 8;
	}
	return ptr;
}


enum symbol {
	ALPHA = (1 << 0),
	NUMERIC = (1 << 2),
	UNDERSCORE = (1 << 3),
	COLON = (1 << 4),
	NEWLINE = (1 << 5),
};

int expect(parser_context* ctx,unsigned int s) {
	if(ctx->buf_index >= CTX_READ_SIZE(ctx)) {
		ctx->premature_eof = 1;
		return 0;
	}
	if((s & ALPHA) && isalpha(ctx->buf[ctx->buf_index])) {
		return 1;
	}
	if((s & NUMERIC) && isdigit(ctx->buf[ctx->buf_index])) {
		return 1;
	}
	if((s & UNDERSCORE) && ctx->buf[ctx->buf_index] == '_') {
		return 1;
	}
	if((s & COLON) && ctx->buf[ctx->buf_index] == ':') {
		return 1;
	}
	if((s & NEWLINE) && ctx->buf[ctx->buf_index] == '\n') {
		return 1;
	}
	return 0;
}
int scan_until(parser_context* ctx,char sentinel) {
	if(ctx->buf_index >= CTX_READ_SIZE(ctx)) {
		ctx->premature_eof = 1;
		return 0;
	}
	off_t ctr = ctx->buf_index;
	for(; ctr < CTX_READ_SIZE(ctx); ctr++) {
		if(ctx->buf[ctr] == sentinel) {
			return ctr;
		}
	}
	return 0;
}

void append_element(parser_context* ctx,tList* e) {
	if(!ctx->users_list) {
		ctx->users_list = ctx->users_list_head = e;
		return;
	}
	ctx->users_list->next = e;
	ctx->users_list = e;
	ctx->users_list->next = NULL;
}
int capture_via_delim(parser_context* ctx,char delim,char** out) {
	int offset_end = scan_until(delim);
	if(offset_end > ctx->buf_index) {
		size_t len = offset_end - ctx->buf_index;
		*out = (char*)pwp_malloc(ctx,len + 1);
		if(ctx->out_of_memory) {
			fprintf(stderr,"OUT OF MEMORY");
			return 0;
		}
		bcopy(&buf[buf_index],*out,len);
		(*out)[len] = 0x0;
		return offset_end;
	}
	return 0;
}

int username(parser_context* ctx) {
	char* uname = NULL;
	int offset_end = capture_via_delim(':',&uname);
	if(offset_end > ctx->buf_index) {
		tList* element = (tList*)pwp_malloc(ctx,sizeof(tList));
		if(ctx->out_of_memory) {
			ctx->error = ERR_OUT_OF_MEMORY;
			return 0;
		}
		memset(element,0,sizeof(tList));
		element->username = uname;
		append_element(ctx,element);
		return offset_end - ctx->buf_index;
	}
	return 0;
}
#if 0
int password() {
	char* p = NULL;
	int offset_end = capture_via_delim(':',&p);
	if(offset_end > buf_index) {
		users_list->password = p;
		return offset_end - buf_index;
	}
	return 0;
}

int parse_uid() {
	char* uid = NULL;
	int offset_end = capture_via_delim(':',&uid);
	if(offset_end > buf_index) {
		users_list->uid = atoi(uid);
		return offset_end - buf_index;
	}
	return 0;
}

int parse_gid() {
	char* gid = NULL;
	int offset_end = capture_via_delim(':',&gid);
	if(offset_end > buf_index) {
		users_list->gid = atoi(gid);
		return offset_end - buf_index;
	}
	return 0;
}

int parse_gecos() {
	if(buf[buf_index] == ':') {
		users_list->gecos_uid = NULL;
		return 0;
	}
	char* gecos = NULL;
	int offset_end = capture_via_delim(':',&gecos);
	if(offset_end > buf_index) {
		users_list->gecos_uid = gecos;
		return offset_end - buf_index;
	}
	return 0;
}
int parse_homedir() {
	char* hd = NULL;
	int offset_end = capture_via_delim(':',&hd);
	if(offset_end > buf_index) {
		users_list->home = hd;
		return offset_end - buf_index;
	}
	return 0;
}
int parse_shell() {
	char* sh = NULL;
	users_list->shell = NULL;
	int offset_end = capture_via_delim('\n',&sh);
	if(offset_end > buf_index) {
		users_list->shell = sh;
		return offset_end - buf_index;
	}
	return 0;
}
void handle_error(int exit_status) {
	char* where = NULL;
	switch(exit_status) {
		case ERR_OPEN:
			where = "open";
			break;
		case ERR_FSTAT:
			where = "fstat";
			break;
		case ERR_MMAP:
			where = "mmap";
			break;
		case ERR_USERNAME:
			where = "expected username";
			break;
		case ERR_COLON:
			where = "expected colon";
			break;
		case ERR_PASSWORD:
			where = "expected password";
			break;
		case ERR_COLON_PASSWORD:
			where = "expected colon after password";
			break;
		case ERR_UID:
			where = "expected UID";
			break;
		case ERR_COLON_UID:
			where = "expected colon after UID";
			break;
		case ERR_GID:
			where = "expected GID";
			break;
		case ERR_COLON_GID:
			where = "expected colon after GID";
			break;
		case ERR_GECOS:
			where = "expected GECOS";
			break;
		case ERR_GECOS_COLON:
			where = "expected colon after GECOS";
			break;
		case ERR_HOMEDIR:
			where = "expected home directory";
			break;
		case ERR_COLON_HOMEDIR:
			where = "expected colon after HOME directory";
			break;
		case ERR_SHELL:
			where = "expected SHELL";
			break;
		case ERR_NEWLINE:
			where = "expected NEWLINE";
			break;
		default:
			where = "unknown";
			break;
	}
	if(line_number) {
		fprintf(stderr,"Failure: '%s' on line %d\n",where,line_number);
	} else {
		fprintf(stderr,"Failure: '%s'\n",where);
	}
}

void dump(parser_context* ctx) {
	assert(ctx != NULL);
#ifdef DEBUG
	int f = 10;
	printf("\n--[ dump ]--\n");
	for(size_t i = buf_index; i < CTX_READ_SIZE(ctx); i++) {
		--f;
		if(f == 0) {
			break;
		}
		printf("%c",buf[i]);
	}
	printf("--[ end dump ]--\n");
#endif
}
#endif

void close_context(parser_context* ctx) {
	if(ctx->buf) {
		munmap(ctx->buf, CTX_READ_SIZE(ctx));
	}
	//FIXME: figure out what to run here to free our
	//resources to the operating system
	if(ctx->fd > -1) {
		close(ctx->fd);
	}
	free_arena(ctx);
}
parser_context* pwp_import(char* file) {
	parser_context* ctx = (parser_context*)malloc(sizeof(parser_context));
	memset(ctx,0,sizeof(parser_context));
	ctx->file_name = file;
	if(ctx->file_name == NULL) {
		ctx->file_name = "/etc/passwd";
	}
	ctx->fd = open(ctx->file_name, O_RDONLY);
	if(ctx->fd == -1) {
		ctx->error = ERR_OPEN;
		return ctx;
	}

	if(fstat(ctx->fd, &(ctx->stats)) == -1) {          /* To obtain file size */
		ctx->error = ERR_FSTAT;
		return ctx;
	}
	init_arena(ctx,(ctx->stats.st_size) * 3);
	return ctx;
}
parser_context* pwp_create() {
	return pwp_import("/etc/passwd");
}
int parse(parser_context* ctx,char* pw_file) {
	ctx->buf_index = 0;
	ctx->buf = NULL;

	ctx->buf = (char*)mmap(NULL, CTX_READ_SIZE(ctx), PROT_READ, MAP_PRIVATE, fd, 0);
	if(addr == MAP_FAILED) {
		return ERR_MMAP;
	}
	buf = addr;

	/** This while loop is essentially int line() */
	while(out_of_memory == 0 && buf_index < read_size && premature_eof == 0) {
		int offset = username();
		if(offset == 0) {
			return ERR_USERNAME;
		}
		buf_index += offset;
		if(!expect(COLON)) {
			return ERR_COLON;
		}
		++buf_index;
		offset = password();
		if(offset == 0) {
			return ERR_PASSWORD;
		}
		buf_index += offset;
		if(!expect(COLON)) {
			return ERR_COLON_PASSWORD;
		}
		++buf_index;
		offset = parse_uid();
		if(offset == 0) {
			return ERR_UID;
		}
		buf_index += offset;
		if(!expect(COLON)) {
			return ERR_COLON_UID;
		}
		++buf_index;
		offset = parse_gid();
		if(offset == 0) {
			return ERR_GID;
		}
		buf_index += offset;
		if(!expect(COLON)) {
			return ERR_COLON_GID;
		}
		++buf_index;
		offset = parse_gecos();
		/**
		 * GECOS field can be empty.
		 * So we don't enforce it here with a check
		 * on whether or not offset will be zero
		 */
		if(offset) {
			buf_index += offset;
		}
		if(!expect(COLON)) {
			return ERR_GECOS_COLON;
		}
		++buf_index;
		offset = parse_homedir();
		if(offset == 0) {
			return ERR_HOMEDIR;
		}
		buf_index += offset;
		if(!expect(COLON)) {
			return ERR_COLON_HOMEDIR;
		}
		++buf_index;
		offset = parse_shell();
		if(offset == 0) {
			return ERR_SHELL;
		}
		buf_index += offset;
		if(!expect(NEWLINE)) {
			return ERR_NEWLINE;
		}
		++buf_index;
		++line_number;
	}
#ifdef DEBUG
	printf("\t[ Bytes in use: %d ]\n",arena_index);
#endif
	tList* ptr = users_list_head;
	while(ptr) {
		printf("%s's shell: %s\n",ptr->username,ptr->shell);
		printf("%s's home: %s\n",ptr->username,ptr->home);
		ptr = ptr->next;
	}

	munmap(addr, length);
	close(fd);


	free_arena();
	return EXIT_SUCCESS;
}

#endif
