#include "main.h"

struct timeval start, end;
long elapsed_time;

unsigned char *str_md5;
size_t md5_size = 0;
size_t md5_capacity = 0;

void save_str_md5(unsigned char *digest) {
    for (int i = 0; i < 16; i++) {
        //printf("%02x", digest[i]);
        if (ensure_md5_buffer_capacity(md5_size + 2)) {
            snprintf(str_md5 + md5_size, 3, "%02x", digest[i]);
            md5_size += 2;
        };
    }
}

bool ensure_md5_buffer_capacity(size_t new_size) {
    if (new_size > md5_capacity) {
        size_t new_capacity = (new_size + 1023) & ~1023; // 1024의 배수로 올림
        char *new_buffer = realloc(str_md5, new_capacity);
        if (new_buffer == NULL) {
            return false;
        }
        str_md5 = new_buffer;
        md5_capacity = new_capacity;
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

void proc_file_or_dir(const char *arg) {
    struct stat st;

    if (stat(arg, &st) != 0) {
        perror("stat");

        return;
    }

    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(arg);

        if (!dir) {
            perror("opendir");

            return;
        }

        struct dirent *entry;

        while((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "md5_value.txt") == 0) {
                continue;
            }

            unsigned char child_path[PATH_MAX];
            snprintf(child_path, sizeof(child_path), "%s/%s", arg, entry->d_name);
            proc_file_or_dir(child_path);
        }

        closedir(dir);
    }
    else if (S_ISREG(st.st_mode)) {
        proc_file(arg);
    }
    else {
        printf("Error proc_file_or_dir");
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

    //FILE *file = fopen(filename, "wb");

    //if (file == NULL) {
    //    perror("fopen");
    //    close(fd);

    //    return ;
    //}

    calc_md5(fd, str_md5, md5_size, digest);

    for (int i = 0; i < 16; i++) {
        sprintf(&md5_string[i*2], "%02x", (unsigned int)digest[i]);
    }

    printf("last calc md5 : %s\n", md5_string);

    //fwrite(md5_string, 1, strlen(md5_string), file);
    //fclose(file);

    close(fd);
}

int main(int argc, char *argv[]) {
    gettimeofday(&start, NULL);

    const char *arg;
    const char *f_name;

    str_md5 = (unsigned char *)calloc(INITIAL_CAPACITY, sizeof(unsigned char));

    if (argc < 2) {
        printf("Usage: %s [file or directory path]\n", argv[0]);

        return 1;
    }

    memset(&start, 0, sizeof(start));
    memset(&end, 0, sizeof(end));
    memset(&elapsed_time, 0, sizeof(elapsed_time));

    arg = argv[1];

    proc_file_or_dir(arg);

    save_md5("md5_value.txt");

    gettimeofday(&end, NULL);

    elapsed_time = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_usec - start.tv_usec);

    printf("Elapsed time: %lf seconds\n", elapsed_time / 1e6);

    if (str_md5 != NULL) {
        free(str_md5);
    }

    return 0;
}