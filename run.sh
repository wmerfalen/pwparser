if [[ "$1" == "--valgrind" ]]; then
	make test && 
		valgrind --leak-check=full -s -- ./build/test-simple-parse /etc/passwd 2>&1 | tee ./valgrind/$(date -I).log &&
		valgrind --leak-check=full -s -- ./build/test-pluck-parse /etc/passwd 2>&1 | tee -a ./valgrind/$(date -I).log

	exit $?
fi
make libtest && ./build/libtest /etc/passwd
