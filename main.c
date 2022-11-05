#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

enum errors {
	ERR_OPEN,
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
	ERR_NEWLINE
};
void dump();

static size_t arena_size = 0;
static char* arena = NULL;
static size_t arena_index = 0;
static int out_of_memory = 0;
void init_arena(size_t sz) {
	arena_size = sz;
	arena = malloc(sz);
}
void free_arena() {
	if(arena) {
		free(arena);
	}
}

void* our_malloc(size_t s) {
	if(arena + s >= arena + arena_size) {
		out_of_memory = 1;
		return NULL;
	}
	void* ptr = &arena[arena_index];
	arena_index += s;
	if(arena_index % 8 != 0) {
		arena_index += 8 - arena_index % 8;
	}
	return ptr;
}

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

enum symbol {
	ALPHA = (1 << 0),
	NUMERIC = (1 << 2),
	UNDERSCORE = (1 << 3),
	COLON = (1 << 4),
	NEWLINE = (1 << 5),
};

static tList* users_list = NULL;
static tList* users_list_head = NULL;
static size_t read_size = 0;
static char* buf = NULL;
static size_t buf_index =  0;
static unsigned int line_number = 0;
static int8_t premature_eof = 0;
int expect(unsigned int s) {
	if(buf_index >= read_size) {
		premature_eof = 1;
		return 0;
	}
	if((s & ALPHA) && isalpha(buf[buf_index])) {
		return 1;
	}
	if((s & NUMERIC) && isdigit(buf[buf_index])) {
		return 1;
	}
	if((s & UNDERSCORE) && buf[buf_index] == '_') {
		return 1;
	}
	if((s & COLON) && buf[buf_index] == ':') {
		return 1;
	}
	if((s & NEWLINE) && buf[buf_index] == '\n') {
		return 1;
	}
	return 0;
}
int scan_until(char sentinel) {
	if(buf_index >= read_size) {
		premature_eof = 1;
		return 0;
	}
	size_t ctr = buf_index;
	for(; ctr < read_size; ctr++) {
		if(buf[ctr] == sentinel) {
			return ctr;
		}
	}
	return 0;
}

void append_element(tList* e) {
	if(!users_list) {
		users_list = (tList*)our_malloc(sizeof(tList));
		if(!users_list) {
			fprintf(stderr,"OUT OF MEMORY");
			out_of_memory = 1;
			return;
		}
		memset(users_list,0,sizeof(tList));
		users_list_head = users_list;
		users_list_head->next = e;
	}
	users_list->next = e;
	users_list = e;
	users_list->next = NULL;
}
int capture_via_delim(char delim,char** out) {
	int offset_end = scan_until(delim);
	if(offset_end > buf_index) {
		size_t len = offset_end - buf_index;
		*out = (char*)our_malloc(len + 1);
		if(out_of_memory) {
			fprintf(stderr,"OUT OF MEMORY");
			return 0;
		}
		bcopy(&buf[buf_index],*out,len);
		(*out)[len] = 0x0;
		return offset_end;
	}
	return 0;
}

int username() {
	char* uname = NULL;
	int offset_end = capture_via_delim(':',&uname);
	if(offset_end > buf_index) {
		tList* element = (tList*)our_malloc(sizeof(tList));
		if(out_of_memory) {
			return 0;
		}
		memset(element,0,sizeof(tList));
		element->username = uname;
		append_element(element);
		return offset_end - buf_index;
	}
	return 0;
}
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
char *addr;
int fd;
struct stat sb;
size_t length;
ssize_t s;
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
	if(addr) {
		munmap(addr, length);
	}
	free_arena();
	if(fd > -1) {
		close(fd);
	}
	exit(exit_status);
}

void dump() {
#ifdef DEBUG
	int f = 10;
	printf("\n--[ dump ]--\n");
	for(size_t i = buf_index; i < read_size; i++) {
		--f;
		if(f == 0) {
			break;
		}
		printf("%c",buf[i]);
	}
	printf("--[ end dump ]--\n");
#endif
}

int main(int argc,char** argv) {
	buf_index = 0;
	addr = NULL;


	fd = open("/etc/passwd", O_RDONLY);
	if(fd == -1) {
		handle_error(ERR_OPEN);
	}

	if(fstat(fd, &sb) == -1) {          /* To obtain file size */
		handle_error(ERR_FSTAT);
	}
	read_size = sb.st_size;
	init_arena(read_size * 3);

	addr = mmap(NULL, read_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(addr == MAP_FAILED) {
		handle_error(ERR_MMAP);
	}
	buf = addr;

	/** This while loop is essentially int line() */
	while(out_of_memory == 0 && buf_index < read_size && premature_eof == 0) {
		int offset = username();
		if(offset == 0) {
			handle_error(ERR_USERNAME);
		}
		buf_index += offset;
		if(!expect(COLON)) {
			handle_error(ERR_COLON);
		}
		++buf_index;
		offset = password();
		if(offset == 0) {
			handle_error(ERR_PASSWORD);
		}
		buf_index += offset;
		if(!expect(COLON)) {
			handle_error(ERR_COLON_PASSWORD);
		}
		++buf_index;
		offset = parse_uid();
		if(offset == 0) {
			handle_error(ERR_UID);
		}
		buf_index += offset;
		if(!expect(COLON)) {
			handle_error(ERR_COLON_UID);
		}
		++buf_index;
		offset = parse_gid();
		if(offset == 0) {
			handle_error(ERR_GID);
		}
		buf_index += offset;
		if(!expect(COLON)) {
			handle_error(ERR_COLON_GID);
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
			handle_error(ERR_GECOS_COLON);
		}
		++buf_index;
		offset = parse_homedir();
		if(offset == 0) {
			handle_error(ERR_HOMEDIR);
		}
		buf_index += offset;
		if(!expect(COLON)) {
			handle_error(ERR_COLON_HOMEDIR);
		}
		++buf_index;
		offset = parse_shell();
		if(offset == 0) {
			handle_error(ERR_SHELL);
		}
		buf_index += offset;
		if(!expect(NEWLINE)) {
			handle_error(ERR_NEWLINE);
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
