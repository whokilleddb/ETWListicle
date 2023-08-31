#include "utils.h"
#include "lister.h"

int main(int argc, char** argv) {
	// Check CLI args
	if (argc != 2) {
		fprintf(stderr, "Usage:\n\t%s <PROCESS NAME>\n", argv[0]);
		return -1;
	}

	// Print details
	printf("[i] Listing ETW providers for:\t\t%s\n", argv[1]);

	// Get Process ID for the target process
	DWORD pid = FindPid(argv[1]);
	if (pid==0) {
		return -1;
	}
	printf("[i] Process ID(PID) of target process:\t%d\n", pid);

	// Try to set Debug privileges for current process
	if (!SetDebugPrivilege()) {
		fprintf(stderr, "[!] Failed to set DEBUG privileges for the current process\n");
	}
	else {
		printf("[i] Set DEBUG privileges for current process\n");
	}

	if (!ParseRegistrationTable(pid)) {
		return -1;
	}


	return 0;
}