#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "blockdevice_file.h"
#include "kvstore_logkvs.h"
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define DEFAULT_KVSTORE_SIZE   128 * 1024


static void show_usage(void) {
    printf("KVSTORE-UTIL:\n"
           "    A command-line tool for development hosts to manage image files of\n"
           "    log-structured key-value stores. It allows you to create image files\n"
           "    and register, browse, list, and delete keys.\n"
           "\n"
           "SYNOPSIS:\n"
           "    kvstore-util create -f <filename> [-s <size>]\n"
           "    kvstore-util set -f <filename> -k <key> -v <value>\n"
           "    kvstore-util get -f <filename> -k <key>\n"
           "    kvstore-util delete -f <filename> -k <key>\n"
           "    kvstore-util find -f <filename> [-k <prefix>]\n"
           "\n"
           "NOTE:\n"
           "    The image files created with this tool can be written to devices using\n"
           "    picotool.\n"
           "\n"
           "    picotool load -o <offset> <filename>\n"
           "\n"
           "    Example: (Writes to the area used by default 'kvs_init()')\n"
           "        picotool load -o 0x101de000 kvstore.bin\n"
           );
}

static size_t image_size(const char *path) {
    struct stat finfo = {0};
    int rc = stat(path, &finfo);
    if (rc != 0 && errno == ENOENT) {
        return 0;
    }
    return (size_t)finfo.st_size;
}

static int command_create(const char *path, size_t size) {
    blockdevice_t *bd = blockdevice_file_create(path, size, 256);
    kvs_t *kvs = kvs_logkvs_create(bd);

    kvs_logkvs_free(kvs);
    blockdevice_file_free(bd);
    truncate(path, size);
    return 0;
}

static int command_get(const char *path, const char *key) {
    size_t size = image_size(path);
    if (size == 0) {
        fprintf(stderr, "File not found. Please 'create' it first\n");
        return 1;
    }
    blockdevice_t *bd = blockdevice_file_create(path, size, 256);
    kvs_t *kvs = kvs_logkvs_create(bd);
    char value[4096] = {0};
    size_t length = 0;
    int rc = kvs->get(kvs, key, value, sizeof(value), &length, 0);
    if (rc == KVSTORE_SUCCESS)
        printf("%s\n", value);
    else if (rc == KVSTORE_ERROR_ITEM_NOT_FOUND)
        fprintf(stderr, "Item not found\n");
    else
        fprintf(stderr, "error rc=%d\n", rc);

    kvs_logkvs_free(kvs);
    blockdevice_file_free(bd);
    return rc;
}

static int command_find(const char *path, const char *prefix) {
    size_t size = image_size(path);
    if (size == 0) {
        fprintf(stderr, "File not found. Please 'create' it first\n");
        return 1;
    }

    blockdevice_t *bd = blockdevice_file_create(path, size, 256);
    kvs_t *kvs = kvs_logkvs_create(bd);

    kvs_find_t ctx;
    int rc = kvs->find(kvs, prefix, &ctx);
    char key[128];
    while (kvs->find_next(kvs, &ctx, key, sizeof(key)) == KVSTORE_SUCCESS) {
        printf("%s\n", key);
    }
    kvs->find_close(kvs, &ctx);

    kvs_logkvs_free(kvs);
    blockdevice_file_free(bd);
    return rc;
}

static int command_set(const char *path, const char *key, const char *value) {
    size_t size = image_size(path);
    if (size == 0) {
        fprintf(stderr, "File not found. Please 'create' it first\n");
        return 1;
    }

    blockdevice_t *bd = blockdevice_file_create(path, size, 256);
    kvs_t *kvs = kvs_logkvs_create(bd);

    int rc = kvs->set(kvs, key, value, strlen(value), 0);
    if (rc != KVSTORE_SUCCESS)
        fprintf(stderr, "Error rc=%d\n", rc);

    kvs_logkvs_free(kvs);
    blockdevice_file_free(bd);
    return rc;
}

static int command_delete(const char *path, const char *key) {
    size_t size = image_size(path);
    if (size == 0) {
        fprintf(stderr, "File not found. Please 'create' it first\n");
        return 1;
    }

    blockdevice_t *bd = blockdevice_file_create(path, size, 256);
    kvs_t *kvs = kvs_logkvs_create(bd);

    int rc = kvs->delete(kvs, key);
    if (rc != KVSTORE_SUCCESS)
        fprintf(stderr, "Error rc=%d\n", rc);
    kvs_logkvs_free(kvs);
    blockdevice_file_free(bd);
    return rc;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        show_usage();
        return 1;
    }

    const char *cmd = argv[1];
    const char *key = NULL;
    const char *value = NULL;
    const char *file = NULL;
    size_t size = DEFAULT_KVSTORE_SIZE;
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
            value = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            file = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            char *endptr;
            size = strtol(argv[++i], &endptr, 10);
            if (size < 8) {
                fprintf(stderr, "-s size is too small\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]);
            return 1;
        }
    }

    if (strcmp(cmd, "create") == 0) {
        if (!file) {
            fprintf(stderr, "create command requires -f <filename>\n");
            return 1;
        }
        return command_create(file, size);

    } else if (strcmp(cmd, "get") == 0) {
        if (!file) {
            fprintf(stderr, "get command requires -f <filename>\n");
            return 1;
        }
        if (key) {
            return command_get(file, key);
        } else {
            return command_find(file, "");
        }
    } else if (strcmp(cmd, "find") == 0) {
        if (!file) {
            fprintf(stderr, "find command requires -f <filename>\n");
            return 1;
        }
        return command_find(file, key);
    } else if (strcmp(cmd, "set") == 0) {
        if (!file || !key || !value) {
            fprintf(stderr, "set command requires -f <filename> -k <key> and -v <value>\n");
            return 1;
        }
        return command_set(file, key, value);
    } else if (strcmp(cmd, "delete") == 0) {
        if (!file || !key) {
            fprintf(stderr, "delete command requires -f <filename> -k <key>\n");
            return 1;
        }
        return command_delete(file, key);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        return 1;
    }

    return 0;
}
