#include <lib/test.h>
#include <lib/string.h>

int
main()
{
    char buf[20];
    int fds[2];
    int ret;

    // create a pipe
    if ((ret = pipe(fds)) != ERR_OK) {
        error("pipe-basic: pipe() failed, return value was %d", ret);
    }

    // write a byte to the pipe
    if ((ret = write(fds[1], "hello world", 11)) != 11) {
        error("pipe-basic: failed to write all buffer content, return value was %d", ret);
    }

    // read a byte from the pipe
    if ((read(fds[0], buf, 5)) != 5) {
        error("pipe-basic: failed to read byte written to pipe, return value was %d", ret);
    }
    buf[5] = 0; // add null terminator

    // check that correct byte was read
    if (strcmp(buf, "hello") != 0) {
        error("pipe-basic: failed to read correct byte from pipe, read %s", buf);
    }

    // read a byte from the pipe
    if ((read(fds[0], buf, 6)) != 6) {
        error("pipe-basic: failed to read byte written to pipe, return value was %d", ret);
    }
    buf[6] = 0; // add null terminator

    // check that correct byte was read
    if (strcmp(buf, " world") != 0) {
        error("pipe-basic: failed to read correct byte from pipe, read %s", buf);
    }

    pass("pipe-count");
    exit(0);
}