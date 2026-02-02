/* A binary that sets up a tmpfs mount, copies a stripped shared object
 * with a debug link into it along with the debug file, and then loads
 * and calls the await_input function from that library.
 *
 * This is designed to be run inside a mount namespace (e.g., via
 * test-mnt-ns.bin) to test symbolization of libraries that have debug
 * links pointing to files only visible within the mount namespace.
 *
 * Usage: test-mnt-ns-child-dbg-link <stripped-so> <debug-file>
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void rm_dir(char **path) {
  int rc;
  int err;

  rc = rmdir(*path);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "warning: failed to remove directory %s: %s (errno: %d)\n",
            *path, strerror(err), err);
  }
}

void unmount(char **path) {
  int rc;
  int err;

  rc = umount(*path);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "warning: failed to unmount %s: %s (errno: %d)\n", *path,
            strerror(err), err);
  }
}

void close_so(void **handle) {
  int rc;
  rc = dlclose(*handle);
  if (rc != 0) {
    fprintf(stderr, "warning: failed to dlclose: %s\n", dlerror());
  }
}

void rm_file(const char **path) {
  int rc;
  int err;

  rc = unlink(*path);
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "warning: failed to remove file %s: %s (errno: %d)\n",
            *path, strerror(err), err);
  }
}

int main(int argc, char **argv) {
  int rc;
  int err;

  if (argc != 3) {
    fprintf(stderr, "usage: %s <stripped-so-with-link> <debug-file>\n",
            argc > 0 ? argv[0] : "<program>");
    return -1;
  }

  char const *lib_src = argv[1];
  char const *dbg_src = argv[2];

  /* Create a temporary directory and mount a ramdisk in there.
   * This should be done inside a mount namespace so that the mount
   * is only visible to this process.
   */
  char tmpl[] = "/tmp/mnt-ns.XXXXXX";
  char *dir = mkdtemp(tmpl);

  if (dir == NULL) {
    err = errno;
    fprintf(stderr, "mkdtemp failed: %s (errno: %d)\n", strerror(err), err);
    return err;
  }
  char *_rm_dir __attribute__((cleanup(rm_dir))) = dir;

  rc = mount("tmpfs", dir, "tmpfs", 0, "size=16M");
  if (rc != 0) {
    err = errno;
    fprintf(stderr, "mount failed: %s (errno: %d)\n", strerror(err), err);
    return err;
  }
  char *_umount __attribute__((cleanup(unmount))) = dir;

  /* Copy the stripped library with debug link to tmpfs. */
  char lib_buf[256];
  rc = snprintf(lib_buf, sizeof(lib_buf), "%s/libtest-so.so", dir);
  if (rc >= sizeof(lib_buf)) {
    fprintf(stderr,
            "failed to construct lib destination path: insufficient buffer space\n");
    return -1;
  }
  lib_buf[rc] = 0;
  char const *lib_dst = lib_buf;

  char cmd_buf[512];
  rc = snprintf(cmd_buf, sizeof(cmd_buf), "cp %s %s", lib_src, lib_dst);
  if (rc >= sizeof(cmd_buf)) {
    fprintf(stderr,
            "failed to construct cp command: insufficient buffer space\n");
    return -1;
  }
  cmd_buf[rc] = 0;

  rc = system(cmd_buf);
  if (rc != 0) {
    fprintf(stderr, "failed to copy %s to %s: %d\n", lib_src, lib_dst, rc);
    return -1;
  }
  const char *_rm_lib __attribute__((cleanup(rm_file))) = lib_dst;

  /* Create usr/lib/debug inside the tmpfs and copy the debug file there.
   * The debug link in the library references the debug file by name, and
   * the symbolizer searches standard debug directories including /usr/lib/debug.
   * By putting the debug file in a path that looks like /usr/lib/debug relative
   * to the library's location, it should only be findable via the mount namespace.
   */
  char debug_dir_buf[256];
  rc = snprintf(debug_dir_buf, sizeof(debug_dir_buf), "%s/usr", dir);
  if (rc >= sizeof(debug_dir_buf)) {
    fprintf(stderr, "failed to construct usr dir path: insufficient buffer space\n");
    return -1;
  }
  if (mkdir(debug_dir_buf, 0755) != 0) {
    err = errno;
    fprintf(stderr, "mkdir %s failed: %s (errno: %d)\n", debug_dir_buf,
            strerror(err), err);
    return err;
  }

  rc = snprintf(debug_dir_buf, sizeof(debug_dir_buf), "%s/usr/lib", dir);
  if (rc >= sizeof(debug_dir_buf)) {
    fprintf(stderr, "failed to construct usr/lib dir path: insufficient buffer space\n");
    return -1;
  }
  if (mkdir(debug_dir_buf, 0755) != 0) {
    err = errno;
    fprintf(stderr, "mkdir %s failed: %s (errno: %d)\n", debug_dir_buf,
            strerror(err), err);
    return err;
  }

  rc = snprintf(debug_dir_buf, sizeof(debug_dir_buf), "%s/usr/lib/debug", dir);
  if (rc >= sizeof(debug_dir_buf)) {
    fprintf(stderr, "failed to construct usr/lib/debug dir path: insufficient buffer space\n");
    return -1;
  }
  if (mkdir(debug_dir_buf, 0755) != 0) {
    err = errno;
    fprintf(stderr, "mkdir %s failed: %s (errno: %d)\n", debug_dir_buf,
            strerror(err), err);
    return err;
  }

  char dbg_buf[256];
  rc = snprintf(dbg_buf, sizeof(dbg_buf), "%s/usr/lib/debug/libtest-so-dwarf-only.dbg", dir);
  if (rc >= sizeof(dbg_buf)) {
    fprintf(stderr,
            "failed to construct dbg destination path: insufficient buffer space\n");
    return -1;
  }
  dbg_buf[rc] = 0;
  char const *dbg_dst = dbg_buf;

  rc = snprintf(cmd_buf, sizeof(cmd_buf), "cp %s %s", dbg_src, dbg_dst);
  if (rc >= sizeof(cmd_buf)) {
    fprintf(stderr,
            "failed to construct cp command: insufficient buffer space\n");
    return -1;
  }
  cmd_buf[rc] = 0;

  rc = system(cmd_buf);
  if (rc != 0) {
    fprintf(stderr, "failed to copy %s to %s: %d\n", dbg_src, dbg_dst, rc);
    return -1;
  }
  const char *_rm_dbg __attribute__((cleanup(rm_file))) = dbg_dst;

  void *handle;
  handle = dlopen(lib_dst, RTLD_NOW);
  if (handle == NULL) {
    fprintf(stderr, "failed to dlopen %s: %s\n", lib_dst, dlerror());
    return -1;
  }
  void *_dlclose __attribute__((cleanup(close_so))) = handle;

  void *(*lookup_private)(void);
  lookup_private = dlsym(handle, "lookup_private");
  if (lookup_private == NULL) {
    fprintf(stderr, "failed to dlsym `lookup_private` function: %s\n", dlerror());
    return -1;
  }

  int (*await_input)(void);
  await_input = dlsym(handle, "await_input");
  if (await_input == NULL) {
    fprintf(stderr, "failed to dlsym `await_input` function: %s\n", dlerror());
    return -1;
  }

  /* Get the address of the private (static) function. This symbol is
   * stripped from .dynsym and can only be symbolized via DWARF debug info.
   */
  void *private_addr = lookup_private();

  /* Write PID and address to stdout for the test harness. */
  pid_t pid = getpid();
  rc = write(STDOUT_FILENO, &pid, sizeof(pid));
  if (rc < 0) {
    perror("failed to write pid to stdout");
    return 1;
  }

  rc = write(STDOUT_FILENO, &private_addr, sizeof(private_addr));
  if (rc < 0) {
    perror("failed to write address to stdout");
    return 1;
  }

  return await_input();
}
