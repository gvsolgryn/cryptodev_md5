#include "main.h"

struct timeval start, end;
long elapsed_time;

unsigned char *str_md5;
size_t md5_size = 0;
size_t md5_capacity = 0;

unsigned char *info_buffer = NULL;
size_t info_size = 0;
size_t info_capacity = 0;

int compare(const void *p1, const void *p2) {
    const char *s1 = *(const char **)p1;
    const char *s2 = *(const char **)p2;
    return strcmp(s1, s2);
}

void save_str_md5(unsigned char *digest) {
    for (int i = 0; i < 16; i++) {
        //printf("%02x", digest[i]);
        if (ensure_md5_buffer_capacity(md5_size + 2)) {
            snprintf(str_md5 + md5_size, 3, "%02x", digest[i]);
            md5_size += 2;
        };
    }
}

void append_file_dir(const char *path) {
    unsigned char *buffer = malloc(PATH_MAX);

    sprintf(buffer, "%s", path);
    strcat(buffer, "\n");

    size_t length = strlen(buffer);

    if (!ensure_info_buffer_capacity(info_size + length)) {
        perror("realloc");
        exit(1);
    }

    memcpy(info_buffer + info_size, buffer, length);
    info_size += length;

    free(buffer);  // 동적 할당한 메모리 해제
}

bool ensure_md5_buffer_capacity(size_t new_size) {
    if (new_size == 0) {
        return true;
    }

    if (new_size > md5_capacity) {
        size_t new_capacity = (new_size + 1023) & ~1023; // 1024의 배수로 올림
        char *new_buffer = realloc(str_md5, new_capacity);

        if (new_buffer == NULL) {
            perror("realloc");
            return false;
        }

        str_md5 = new_buffer;
        md5_capacity = new_capacity;
    }

    return true;
}

bool ensure_info_buffer_capacity(size_t new_size) {
    if (new_size == 0) {
        return true;
    }

    if (new_size >= info_capacity) {
        size_t new_capacity = (new_size + 1023) & ~1023;
        unsigned char *new_buffer = realloc(info_buffer, new_capacity);

        if (new_buffer == NULL) {
            perror("realloc");
            return false;
        }

        info_buffer = new_buffer;
        info_capacity = new_capacity;
    }

    return true;
}

void calc_md5(int fd, unsigned char *buffer, size_t size, unsigned char *digest) {
    struct session_op sess;
    struct crypt_op cryp;

    memset(&sess, 0, sizeof(sess));
    memset(&cryp, 0, sizeof(cryp));

    sess.cipher = 0;
    sess.mac = CRYPTO_MD5;

    if (ioctl(fd, CIOCGSESSION, &sess) < 0) {
        perror("CIOCGSESSION");
        close(fd);
        return;
    }

    cryp.ses = sess.ses;
    cryp.len = size;
    cryp.src = buffer;
    cryp.dst = NULL;
    cryp.mac = digest;

    if (ioctl(fd, CIOCCRYPT, &cryp) < 0) {
        perror("CIOCCRYPT");
        close(fd);
        return;
    }

    if (ioctl(fd, CIOCFSESSION, &sess.ses) < 0) {
        perror("CIOCFSESSION");
        close(fd);
        return;
    }
}

void proc_file(const char *filename) {
    int fd, res;
    unsigned char digest[16];
    
    fd = open("/dev/crypto", O_RDWR);
    if (fd < 0) {
        perror("open");
        return;
    }

    FILE *file = fopen(filename, "rb");

    if (file == NULL) {
        perror("fopen");
        close(fd);
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = malloc(file_size);
    fread(buffer, 1, file_size, file);
    fclose(file);

    calc_md5(fd, buffer, file_size, digest);

    //printf("MD5: ");
    save_str_md5(digest);
    //printf("\n");

    close(fd);

    free(buffer);
}

void proc_dir(const char *arg) {
    DIR *dir = opendir(arg);

    if(dir == NULL) {
        perror("opendir");

        return;
    }

    struct dirent *entry;

    while((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "md5_value.txt") == 0) {
            continue;
        }

        char path[PATH_MAX];

        snprintf(path, sizeof(path), "%s/%s", arg, entry->d_name);

        struct stat st;

        if (lstat(path, &st) < 0) {
            perror("lstat");

            continue;
        }

        append_file_dir(path);

        if(S_ISDIR(st.st_mode)) {
            proc_dir(path);
        }
    }

    closedir(dir);
}

void check_file_or_dir(const char *arg) {
    struct stat st;

    if (stat(arg, &st) != 0) {
        perror("stat");

        return;
    }

    if (S_ISDIR(st.st_mode)) {
        /*DIR *dir = opendir(arg);

        if (!dir) {
            perror("opendir");

            return;
        }

        struct dirent *entry;

        while((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "md5_value.txt") == 0) {
                continue;
            }

            unsigned char path[PATH_MAX];

            snprintf(path, sizeof(path), "%s/%s", arg, entry->d_name);

            struct stat status;

            if (lstat(path, &status) < 0) {
                perror("lstat");
                continue;
            }

            append_file_dir(path);

            check_file_or_dir(path);
        }

        closedir(dir);*/
        return;
    }
    else if (S_ISREG(st.st_mode)) {
        proc_file(arg);
    }
    else {
        printf("Error check_file_or_dir");
    }
}

void save_md5(const char *filename) {
    int fd;
    unsigned char digest[16];
    unsigned char md5_string[32];

    fd = open("/dev/crypto", O_RDWR);
    if (fd < 0) {
        perror("open");

        return;
    }

    calc_md5(fd, str_md5, md5_size, digest);

    for (int i = 0; i < 16; i++) {
        sprintf(&md5_string[i*2], "%02x", (unsigned int)digest[i]);
    }

    printf("last calc md5 : %s\n", md5_string);

    // save_txt("md5_value.txt", md5_string);

    close(fd);
}

void sort_info_buffer() {
    unsigned char *tmp_buffer = malloc(info_size);
    if (tmp_buffer == NULL) {
        perror("malloc");
        exit(1);
    }
    memcpy(tmp_buffer, info_buffer, info_size);
    
    size_t count = 0;
    char **str_array = malloc(INITIAL_CAPACITY * sizeof(char *));
    if (str_array == NULL) {
        perror("malloc");
        exit(1);
    }

    char *token = strtok(tmp_buffer, "\n");
    while (token != NULL) {
        str_array[count++] = token;
        token = strtok(NULL, "\n");
    }
    
    qsort(str_array, count, sizeof(char *), compare);
    
    size_t pos = 0;
    for (size_t i = 0; i < count; i++) {
        size_t length = strlen(str_array[i]);

        if (!ensure_info_buffer_capacity(pos + length + 1)) {
            perror("realloc");
            exit(1);
        }

        memcpy(info_buffer + pos, str_array[i], length);
        pos += length;

        info_buffer[pos++] = '\n';
    }
    
    info_size = pos;
    
    free(tmp_buffer);
    free(str_array);
}

void save_txt(const char *filename, const unsigned char *buffer) {
    FILE *file = fopen(filename, "wb");

    if(file == NULL) {
        perror("fopen");

        return;
    }

    fwrite(buffer, 1, strlen(buffer), file);
    fclose(file);

    printf("Directory buffer save to %s.\r\n", filename);
}

int main(int argc, char *argv[]) {
    memset(&start, 0, sizeof(start));
    memset(&end, 0, sizeof(end));
    memset(&elapsed_time, 0, sizeof(elapsed_time));

    gettimeofday(&start, NULL);

    str_md5 = (unsigned char *)calloc(INITIAL_CAPACITY, sizeof(unsigned char));

    if (argc < 2) {
        printf("Usage: %s [file or directory path]\n", argv[0]);

        return 1;
    }

    proc_dir(argv[1]);

    save_md5("md5_value.txt");

    save_txt("file_info_md5test.txt", info_buffer);

    sort_info_buffer();

    save_txt("file_info_md5test_sorted.txt", info_buffer);

    gettimeofday(&end, NULL);

    elapsed_time = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_usec - start.tv_usec);

    printf("Elapsed time: %lf seconds\n", elapsed_time / 1e6);

    if (str_md5 != NULL) {
        free(str_md5);
    }

    return 0;
}