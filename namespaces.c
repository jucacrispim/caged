/*
  Copyright 2026 Juca Crispim <juca@poraodojuca.dev>

  This file is part of caged.

  caged is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  caged is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with caged. If not, see <http://www.gnu.org/licenses/>.
*/

/*
  The namespaces the command can be given: a user namespace that makes the
  others possible, a mount namespace with private directories and a network
  namespace holding nothing but loopback.
*/

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "caged_internal.h"

int caged_write_file(const char *path, const char *text) {
  size_t len = strlen(text);
  int fd = open(path, O_WRONLY | O_CLOEXEC);

  if (fd < 0) {
    return -1;
  }
  ssize_t written = write(fd, text, len);
  int write_errno = errno;
  close(fd);
  if (written < 0) {
    errno = write_errno;
    return -1;
  }
  if ((size_t)written != len) {
    /*
      If written bytes is different than the text len it is a error
      because a trucated write could match a wrong user.
     */
    errno = EIO;
    return -1;
  }
  return 0;
}

/*
  Writes an id map that maps the caller's own id to itself.
*/
int caged_write_id_map(const char *path, unsigned int id) {
  char map[64];

  (void)snprintf(map, sizeof map, "%u %u 1\n", id, id);
  return caged_write_file(path, map);
}

/*
  Brings loopback up in the current network namespace.
  When a new namespace is created, a loopback interface is
  created but it's down.
*/
int caged_loopback_up(void) {
  struct ifreq ifr = {0};
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

  if (fd < 0) {
    return -1;
  }
  memcpy(ifr.ifr_name, "lo", sizeof "lo");
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
    close(fd);
    return -1;
  }
  ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_UP);
  if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

/*
  Removes every capability from the process.

  An EINVAL from PR_CAPBSET_DROP only means this kernel does not know the
  capability number, so it is not a failure.
*/
int caged_drop_capabilities(void) {
  struct __user_cap_header_struct header = {
      .version = _LINUX_CAPABILITY_VERSION_3,
      .pid = 0,
  };
  struct __user_cap_data_struct data[2] = {{0}};

  for (int c = 0; c <= CAP_LAST_CAP; c++) {
    if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) < 0 && errno != EINVAL) {
      return -1;
    }
  }
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
    return -1;
  }
  if (syscall(SYS_capset, &header, data) < 0) {
    return -1;
  }
  return 0;
}

/*
  Creates a user namespace that maps the caller's own ids to themselves.
*/
enum caged_return caged_setup_userns(void) {
  unsigned int uid = (unsigned int)geteuid();
  unsigned int gid = (unsigned int)getegid();

  if (unshare(CLONE_NEWUSER) < 0) {
    return CAGED_ERR_USERNS_UNAVAILABLE;
  }
  /*
    Writing "deny" to setgroups is what lets an unprivileged process write a
    gid map.
  */
  if (caged_write_file(CAGED_PROC_SELF_SETGROUPS, "deny") < 0) {
    return CAGED_ERR_USERNS_MAP;
  }
  if (caged_write_id_map(CAGED_PROC_SELF_UID_MAP, uid) < 0) {
    return CAGED_ERR_USERNS_MAP;
  }
  if (caged_write_id_map(CAGED_PROC_SELF_GID_MAP, gid) < 0) {
    return CAGED_ERR_USERNS_MAP;
  }
  return CAGED_OK;
}

/*
  Creates the mount namespace the private directories of the sandbox live in.

  "/" is made recursively private before anything is mounted: CLONE_NEWNS
  copies the mount list but not the propagation, so a mount here would
  otherwise reach the host's peer groups.
*/
enum caged_return caged_setup_mountns(void) {
  if (unshare(CLONE_NEWNS) < 0) {
    return CAGED_ERR_MOUNT;
  }
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
    return CAGED_ERR_MOUNT;
  }
  return CAGED_OK;
}

/* Mounts a fresh, capped, nosuid/nodev tmpfs over `target`. */
int caged_mount_tmpfs(const char *target) {
  return mount("tmpfs", target, "tmpfs", MS_NOSUID | MS_NODEV,
               CAGED_PRIVATE_TMPFS_OPTS);
}

/*
  Gives the process a /tmp of its own.

  `src` NULL means a fresh tmpfs; otherwise `src` is bind-mounted over /tmp,
  which is what a caller that still has to exchange files with the sandbox
  needs.
*/
enum caged_return caged_setup_private_tmp(const char *src) {
  if (src == NULL) {
    return caged_mount_tmpfs(CAGED_PRIVATE_TMP) < 0 ? CAGED_ERR_MOUNT
                                                    : CAGED_OK;
  }
  if (mount(src, CAGED_PRIVATE_TMP, NULL, MS_BIND | MS_REC, NULL) < 0) {
    return CAGED_ERR_MOUNT;
  }
  /*
    A bind mount inherits the source's flags, so a second mount() is what
    applies nosuid and nodev to it.
  */
  if (mount(NULL, CAGED_PRIVATE_TMP, NULL,
            MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV, NULL) < 0) {
    return CAGED_ERR_MOUNT;
  }
  return CAGED_OK;
}

/*
  Gives the process a /dev/shm of its own: a fresh tmpfs in the mount
  namespace, sharing nothing with the host.
*/
enum caged_return caged_setup_private_shm(void) {
  if (caged_mount_tmpfs(CAGED_PRIVATE_SHM) < 0) {
    return CAGED_ERR_MOUNT;
  }
  return CAGED_OK;
}

/*
  Creates a network namespace holding nothing but a working loopback.
*/
enum caged_return caged_setup_netns(void) {
  if (unshare(CLONE_NEWNET) < 0) {
    return CAGED_ERR_NETNS;
  }
  if (caged_loopback_up() < 0) {
    return CAGED_ERR_NETNS;
  }
  return CAGED_OK;
}

/*
  Builds the namespaces the command will run in.

  First create the user namespace and after that
  create the mounts for /tmp and /dev/shm and the
  net namespace for loopback
*/
enum caged_return caged_setup_namespaces(int private_tmp,
                                         const char *private_tmp_src,
                                         int private_shm, int loopback_only) {
  enum caged_return r = caged_setup_userns();

  if (r != CAGED_OK) {
    return r;
  }
  if (private_tmp || private_shm) {
    r = caged_setup_mountns();
    if (r != CAGED_OK) {
      return r;
    }
  }
  if (private_tmp) {
    r = caged_setup_private_tmp(private_tmp_src);
    if (r != CAGED_OK) {
      return r;
    }
  }
  if (private_shm) {
    r = caged_setup_private_shm();
    if (r != CAGED_OK) {
      return r;
    }
  }
  if (loopback_only) {
    r = caged_setup_netns();
    if (r != CAGED_OK) {
      return r;
    }
  }
  if (caged_drop_capabilities() < 0) {
    return CAGED_ERR_CAPABILITIES;
  }
  return CAGED_OK;
}
