#ifndef __ETC_PASSWD_PARSER_LIB_HEADER__
#define __ETC_PASSWD_PARSER_LIB_HEADER__

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define CTX_BUF_SZ(c) c->stats.st_size

enum target_columns {
	T_USERNAME = (1 << 0),
	T_PASSWORD = (1 << 1),
	T_UID = (1 << 2),
	T_GID = (1 << 3),
	T_GECOS = (1 << 4),
	T_HOME = (1 << 5),
	T_SHELL = (1 << 6),
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

typedef int(*row_callback)(tList*);
typedef int(*column_callback)(int column,char* ptr,unsigned int* i_ptr);

enum {
	CB_STOP_ITERATING,
	CB_KEEP_ITERATING,
};

typedef struct _parser_context {
	int mask;
	char* buf;
	off_t buf_index;
	char* file_name;
	struct stat stats;
	int fd;
	int stage;
	size_t arena_index;
	size_t arena_size;
	void* arena;
	tList* users_list;
	tList* users_list_head;
	unsigned int line_number;
	int8_t premature_eof;
	int8_t out_of_memory;
	int error;
	row_callback* row_cb;
	column_callback* column_cb;
} parser_context;


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
	ERR_NO_FILE_SPECIFIED,
	ERR_MUST_CALL_CREATE,
};
const char* pwp_strerror(int error_code) {
	static const char* where = NULL;
	switch(error_code) {
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
	return where;
}


void init_arena(parser_context* ctx,size_t sz) {
	ctx->arena_size = sz;
	ctx->arena = malloc(ctx->arena_size);
}
void double_arena(parser_context* ctx) {
	ctx->arena_size *= 2;
	ctx->arena = realloc(ctx->arena,ctx->arena_size);
}

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
	if(ctx->buf_index >= CTX_BUF_SZ(ctx)) {
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
	if(ctx->buf_index >= CTX_BUF_SZ(ctx)) {
		ctx->premature_eof = 1;
		return 0;
	}
	off_t ctr = ctx->buf_index;
	for(; ctr < CTX_BUF_SZ(ctx); ctr++) {
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
	int offset_end = scan_until(ctx,delim);
	if(offset_end > ctx->buf_index) {
		size_t len = offset_end - ctx->buf_index;
		*out = (char*)pwp_malloc(ctx,len + 1);
		assert(!ctx->out_of_memory);
		bcopy(&ctx->buf[ctx->buf_index],*out,len);
		(*out)[len] = 0x0;
		return offset_end;
	}
	return 0;
}

int parse_username(parser_context* ctx) {
	char* uname = NULL;
	int offset_end = capture_via_delim(ctx,':',&uname);
	if(offset_end > ctx->buf_index) {
		tList* element = (tList*)pwp_malloc(ctx,sizeof(tList));
		assert(!ctx->out_of_memory);
		memset(element,0,sizeof(tList));
		element->username = uname;
		append_element(ctx,element);
		return offset_end - ctx->buf_index;
	}
	return 0;
}
int parse_password(parser_context* ctx) {
	char* p = NULL;
	int offset_end = capture_via_delim(ctx,':',&p);
	if(offset_end > ctx->buf_index) {
		ctx->users_list->password = p;
		return offset_end - ctx->buf_index;
	}
	return 0;
}

int parse_uid(parser_context* ctx) {
	char* uid = NULL;
	int offset_end = capture_via_delim(ctx,':',&uid);
	if(offset_end > ctx->buf_index) {
		ctx->users_list->uid = atoi(uid);
		return offset_end - ctx->buf_index;
	}
	return 0;
}

int parse_gid(parser_context* ctx) {
	char* gid = NULL;
	int offset_end = capture_via_delim(ctx,':',&gid);
	if(offset_end > ctx->buf_index) {
		ctx->users_list->gid = atoi(gid);
		return offset_end - ctx->buf_index;
	}
	return 0;
}

int parse_gecos(parser_context* ctx) {
	if(ctx->buf[ctx->buf_index] == ':') {
		ctx->users_list->gecos_uid = NULL;
		return 0;
	}
	char* gecos = NULL;
	int offset_end = capture_via_delim(ctx,':',&gecos);
	if(offset_end > ctx->buf_index) {
		ctx->users_list->gecos_uid = gecos;
		return offset_end - ctx->buf_index;
	}
	return 0;
}
int parse_homedir(parser_context* ctx) {
	char* hd = NULL;
	int offset_end = capture_via_delim(ctx,':',&hd);
	if(offset_end > ctx->buf_index) {
		ctx->users_list->home = hd;
		return offset_end - ctx->buf_index;
	}
	return 0;
}
int parse_shell(parser_context* ctx) {
	char* sh = NULL;
	ctx->users_list->shell = NULL;
	int offset_end = capture_via_delim(ctx,'\n',&sh);
	if(offset_end > ctx->buf_index) {
		ctx->users_list->shell = sh;
		return offset_end - ctx->buf_index;
	}
	return 0;
}

void free_arena(parser_context* ctx) {
	assert(ctx != NULL);
	if(ctx) {
		if(ctx->arena) {
			ctx->arena_size = 0;
			free(ctx->arena);
			ctx->arena = NULL;
		}
	}
}

void pwp_close(parser_context* ctx) {
	if(ctx->buf) {
		munmap((char*)ctx->buf, CTX_BUF_SZ(ctx));
	}
	if(ctx->fd > -1) {
		close(ctx->fd);
	}
	free_arena(ctx);
	free(ctx);
}
enum stage {
	STAGE_INIT = 0,
	STAGE_FILE_OPENED,
	STAGE_STATS_FETCHED,
	STAGE_FILE_MAPPED,
	STAGE_READY,
};
parser_context* pwp_create_from(const char* file) {
	parser_context* ctx = (parser_context*)malloc(sizeof(parser_context));
	memset(ctx,0,sizeof(parser_context));
	ctx->stage = STAGE_INIT;
	ctx->file_name = (char*)file;
	if(ctx->file_name == NULL) {
		ctx->error = ERR_NO_FILE_SPECIFIED;
		return ctx;
	}
	ctx->fd = open(ctx->file_name, O_RDONLY);
	if(ctx->fd == -1) {
		ctx->error = ERR_OPEN;
		return ctx;
	}
	ctx->stage = STAGE_FILE_OPENED;

	if(fstat(ctx->fd, &(ctx->stats)) == -1) {          /* To obtain file size */
		ctx->error = ERR_FSTAT;
		return ctx;
	}
	ctx->stage = STAGE_STATS_FETCHED;
	ctx->buf = (char*)mmap(NULL, CTX_BUF_SZ(ctx), PROT_READ, MAP_PRIVATE, ctx->fd, 0);
	if(ctx->buf == MAP_FAILED) {
		ctx->error = ERR_MMAP;
		return ctx;
	}
	ctx->stage = STAGE_FILE_MAPPED;
	init_arena(ctx,(ctx->stats.st_size) * 3);
	ctx->stage = STAGE_READY;
	return ctx;
}
parser_context* pwp_create(char* file) {
	if(file) {
		return pwp_create_from(file);
	}
	return pwp_create_from("/etc/passwd");
}
enum parse_result {
	PARSE_ERR_MUST_CALL_CREATE = -1,
	PARSE_ERR_SYNTAX_ERROR = -2,
	PARSE_ERR_LOGIC_ERROR = -3,
	PARSE_OK = 0,
};


int pwp_parse(parser_context* ctx) {
	if(ctx->stage < STAGE_READY) {
		ctx->error = ERR_MUST_CALL_CREATE;
		return PARSE_ERR_MUST_CALL_CREATE;
	}

	int8_t keep_parsing= 1;
	/** This while loop is essentially int line() */
	while(keep_parsing &&
	    ctx->buf_index < CTX_BUF_SZ(ctx) &&
	    ctx->premature_eof == 0) {
		int offset = parse_username(ctx);
		if(offset == 0) {
			ctx->error = ERR_USERNAME;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		ctx->buf_index += offset;
		if(!expect(ctx,COLON)) {
			ctx->error = ERR_COLON;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		++ctx->buf_index;
		offset = parse_password(ctx);
		if(offset == 0) {
			ctx->error = ERR_PASSWORD;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		ctx->buf_index += offset;
		if(!expect(ctx,COLON)) {
			ctx->error = ERR_COLON_PASSWORD;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		++ctx->buf_index;
		offset = parse_uid(ctx);
		if(offset == 0) {
			ctx->error = ERR_UID;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		ctx->buf_index += offset;
		if(!expect(ctx,COLON)) {
			ctx->error = ERR_COLON_UID;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		++ctx->buf_index;
		offset = parse_gid(ctx);
		if(offset == 0) {
			ctx->error = ERR_GID;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		ctx->buf_index += offset;
		if(!expect(ctx,COLON)) {
			ctx->error = ERR_COLON_GID;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		++ctx->buf_index;
		offset = parse_gecos(ctx);
		/**
		 * GECOS field can be empty.
		 * So we don't enforce it here with a check
		 * on whether or not offset will be zero
		 */
		if(offset) {
			ctx->buf_index += offset;
		}
		if(!expect(ctx,COLON)) {
			ctx->error = ERR_GECOS_COLON;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		++ctx->buf_index;
		offset = parse_homedir(ctx);
		if(offset == 0) {
			ctx->error = ERR_HOMEDIR;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		ctx->buf_index += offset;
		if(!expect(ctx,COLON)) {
			ctx->error = ERR_COLON_HOMEDIR;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		++ctx->buf_index;
		offset = parse_shell(ctx);
		if(offset == 0) {
			ctx->error = ERR_SHELL;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		ctx->buf_index += offset;
		if(!expect(ctx,NEWLINE)) {
			ctx->error = ERR_NEWLINE;
			return PARSE_ERR_SYNTAX_ERROR;
		}
		++ctx->buf_index;
		++(ctx->line_number);
		if(ctx->row_cb != NULL) {
			int result = (*(ctx->row_cb))(ctx->users_list);
			switch(result) {
				case CB_STOP_ITERATING:
					keep_parsing = 0;
					continue;
				default:
				/** Fall-through behaviour is intentional */
				case CB_KEEP_ITERATING:
					keep_parsing = 1;
					break;
			}
		}
	}

#define SHOULD_STOP(s) if(s == CB_STOP_ITERATING){ break; }
	if(ctx->column_cb) {
		tList* ptr = ctx->users_list_head;
		while(ptr) {
			int status = 0;
			if(ctx->mask & T_USERNAME) {
				status = (*(ctx->column_cb))(T_USERNAME,ptr->username,NULL);
				SHOULD_STOP(status);
			}
			if(ctx->mask & T_PASSWORD) {
				status = (*(ctx->column_cb))(T_PASSWORD,ptr->password,NULL);
				SHOULD_STOP(status);
			}
			if(ctx->mask & T_UID) {
				status = (*(ctx->column_cb))(T_UID,NULL,&ptr->uid);
				SHOULD_STOP(status);
			}
			if(ctx->mask & T_GID) {
				status = (*(ctx->column_cb))(T_GID,NULL,&ptr->gid);
				SHOULD_STOP(status);
			}
			if(ctx->mask & T_GECOS) {
				status = (*(ctx->column_cb))(T_GECOS,ptr->gecos_uid,NULL);
				SHOULD_STOP(status);
			}
			if(ctx->mask & T_HOME) {
				status = (*(ctx->column_cb))(T_HOME,ptr->home,NULL);
				SHOULD_STOP(status);
			}
			if(ctx->mask & T_SHELL) {
				status = (*(ctx->column_cb))(T_SHELL,ptr->shell,NULL);
				SHOULD_STOP(status);
			}
			ptr = ptr->next;
		}
	}

	return PARSE_OK;
}

/**
 * column_mask is the bitmask combination of T_* enums.
 * Example:
 * pwp_pluck_column(ctx, (T_USERNAME | T_SHELL | T_UID), callback);
 */
int pwp_pluck_column(parser_context* ctx, int column_mask, column_callback* cb) {
	if(!ctx) {
		return PARSE_ERR_LOGIC_ERROR;
	}
	ctx->column_cb = cb;
	ctx->mask = column_mask;
	return pwp_parse(ctx);
}

#endif
