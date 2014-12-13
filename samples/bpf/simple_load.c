#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"

int main(int ac, char **argv)
{
	char filename[256];

	if (ac < 2) {
		printf("Usage: %s <elf>\n", argv[0]);
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s", argv[1]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	printf("Loaded.");

	sleep(600);

	return 0;
}
