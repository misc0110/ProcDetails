#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    char proc[256];
    char *line = NULL, *module = NULL;
    size_t len = 0, total = 0;
    ssize_t read;

    if(argc != 2) {
        printf("Usage: %s <proc filename>\n", argv[0]);
        return -1;
    }
    
    proc[255] = 0;
    if((module = strrchr(argv[1], '/')) != NULL) {
        strncpy(proc, module + 1, 255);
    } else {
        strncpy(proc, argv[1], 255);
    }

    FILE* f = fopen("/proc/procdetails", "w");
    if(!f) {
        fprintf(stderr, "Could not find /proc/procdetails! Did you load the procdetails kernel module?\n");
        return -1;
    }
    fputs(proc, f);
    fclose(f);
    f = fopen("/proc/procdetails", "r");
    if(!f) {
        fprintf(stderr, "Something strange happened...\n");
        return -1;
    }

    while ((read = getline(&line, &len, f)) != -1) {
        total += len;
        printf("%s", line);
    }
    free(line);
    fclose(f);

    if(!total) {
        printf("Did not find any information\n");
        return -1;
    }
    return 0;
}
