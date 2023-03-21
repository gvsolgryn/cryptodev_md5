#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <linux/limits.h>

#include <crypto/cryptodev.h>

#define INITIAL_CAPACITY 1024

void save_str_md5(unsigned char *digest);
bool ensure_md5_buffer_capacity(size_t new_size);
void calc_md5(int fd, unsigned char *buffer, size_t size, unsigned char *digest);
void proc_file(const char *filename);
void proc_file_or_dir(const char *arg);
void save_md5(const char *filename);