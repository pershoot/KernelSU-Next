#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define SUSFS_MAGIC 0xFAFAFAFA

#define CMD_SUSFS_SHOW_VERSION 0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES 0x555e2
#define CMD_SUSFS_SHOW_VARIANT 0x555e3

#define SUSFS_ENABLED_FEATURES_SIZE 8192
#define SUSFS_MAX_VERSION_BUFSIZE 16
#define SUSFS_MAX_VARIANT_BUFSIZE 16

#define ERR_CMD_NOT_SUPPORTED 126
#define PRT_MSG_IF_CMD_NOT_SUPPORTED(x, cmd) \
    do { if ((x) == ERR_CMD_NOT_SUPPORTED) fprintf(stderr, "[-] CMD: '0x%x', SUSFS operation not supported, please enable it in kernel\n", (cmd)); } while(0)

struct st_susfs_version {
    char susfs_version[SUSFS_MAX_VERSION_BUFSIZE];
    int err;
};

struct st_susfs_variant {
    char susfs_variant[SUSFS_MAX_VARIANT_BUFSIZE];
    int err;
};

struct st_susfs_enabled_features {
    char enabled_features[SUSFS_ENABLED_FEATURES_SIZE];
    int err;
};

int main(int argc, char *argv[]) {
    // Check for arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <support|version|variant|features>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "version") == 0) {
        struct st_susfs_version vinfo = {0};
        vinfo.err = ERR_CMD_NOT_SUPPORTED;
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_VERSION, &vinfo);
        PRT_MSG_IF_CMD_NOT_SUPPORTED(vinfo.err, CMD_SUSFS_SHOW_VERSION);
        if (!vinfo.err) {
            printf("%s\n", vinfo.susfs_version);
        } else {
            printf("Invalid\n");
        }
    } else if (strcmp(argv[1], "variant") == 0) {
        struct st_susfs_variant varinfo = {0};
        varinfo.err = ERR_CMD_NOT_SUPPORTED;
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_VARIANT, &varinfo);
        PRT_MSG_IF_CMD_NOT_SUPPORTED(varinfo.err, CMD_SUSFS_SHOW_VARIANT);
        if (!varinfo.err) {
            printf("%s\n", varinfo.susfs_variant);
        } else {
            printf("Invalid\n");
        }
    } else if (strcmp(argv[1], "features") == 0) {
        struct st_susfs_enabled_features finfo = {0};
        finfo.err = ERR_CMD_NOT_SUPPORTED;
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_ENABLED_FEATURES, &finfo);
        PRT_MSG_IF_CMD_NOT_SUPPORTED(finfo.err, CMD_SUSFS_SHOW_ENABLED_FEATURES);
        if (!finfo.err && strlen(finfo.enabled_features) > 0) {
            printf("%s", finfo.enabled_features);
        } else {
            printf("Invalid\n");
        }
    } else if (strcmp(argv[1], "support") == 0) {
        struct st_susfs_enabled_features finfo = {0};
        finfo.err = ERR_CMD_NOT_SUPPORTED;
        syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_ENABLED_FEATURES, &finfo);
        PRT_MSG_IF_CMD_NOT_SUPPORTED(finfo.err, CMD_SUSFS_SHOW_ENABLED_FEATURES);
        if (!finfo.err && strlen(finfo.enabled_features) > 0) {
            printf("Supported\n");
        } else {
            printf("Unsupported\n");
        }
    } else {
        fprintf(stderr, "Invalid argument: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
