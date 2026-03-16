#include <sys/fanotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>


int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("USAGE: hide_pid <PID>\n");
        exit(1);
    }

    int res;

    char *pid = argv[1];
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s", pid);

    struct stat info;
    if (stat(path, &info) != 0){
        if (errno == ENOENT || errno == ENOTDIR) {
            printf("input process does not exist");
        }
        else printf("stat failed for another reason");
        exit(1);
    }

    // this is a kernel object that is responsible for holding all file-system events and deliver them to me. 
    // Basically a communication channel between the kernel object and my intercepting process.
    int fd = fanotify_init(FAN_CLASS_PRE_CONTENT, O_RDONLY);
    if (fd == -1) {
        perror("fanotify_init");
        exit(1);
    }

    res = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN_PERM, AT_FDCWD, path);
    if (res == -1){
        perror("fanotify_mark");
        exit(1);
    }

    char buffer[4096];

    while (1) {
        int len = read(fd, buffer, sizeof(buffer));
        struct fanotify_event_metadata *metadata = (struct fanotify_event_metadata *)buffer;

        if (metadata->mask & FAN_OPEN_PERM) {
            printf("Intercepted open from PID %d\n", metadata->pid);

            struct fanotify_response response;
            response.fd = metadata->fd;

            response.response = FAN_DENY;

            if (write(fd, &response, sizeof(response)) == -1) {
                perror("write FAN_OPEN_PERM response");
            }
        }

        close(metadata->fd);
    }
}