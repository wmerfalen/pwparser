if [[ "$1" == "--valgrind" ]]; then
	make libtest && valgrind --leak-check=full -s -- ./build/libtest /etc/passwd 2>&1 | tee ./valgrind/$(date -I).log
	exit $?
fi
make libtest && ./build/libtest /etc/passwd
