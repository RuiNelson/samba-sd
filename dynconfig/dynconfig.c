/*
   Unix SMB/CIFS implementation.
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) Stefan Metzmacher	2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file dynconfig.c
 *
 * @brief Global configurations, initialized to configured defaults.
 *
 * This file should be the only file that depends on path
 * configuration (--prefix, etc), so that if ./configure is re-run,
 * all programs will be appropriately updated.  Everything else in
 * Samba should import extern variables from here, rather than relying
 * on preprocessor macros.
 *
 * Eventually some of these may become even more variable, so that
 * they can for example consistently be set across the whole of Samba
 * by command-line parameters, config file entries, or environment
 * variables.
 *
 * @todo Perhaps eventually these should be merged into the parameter
 * table?  There's kind of a chicken-and-egg situation there...
 **/

#include "replace.h"
#include "dynconfig.h"
#include "lib/util/memory.h"

#define DEFINE_DYN_CONFIG_PARAM(name) \
const char *dyn_##name = name; \
\
bool is_default_dyn_##name(void) \
{\
	if (strcmp(name, dyn_##name) == 0) { \
		return true; \
	} \
	return false; \
}\
\
const char *get_dyn_##name(void) \
{\
	return dyn_##name;\
}\
\
const char *set_dyn_##name(const char *newpath) \
{\
	if (newpath == NULL) { \
		return NULL; \
	} \
	if (strcmp(name, newpath) == 0) { \
		return dyn_##name; \
	} \
	newpath = strdup(newpath);\
	if (newpath == NULL) { \
		return NULL; \
	} \
	if (is_default_dyn_##name()) { \
		/* do not free a static string */ \
	} else if (dyn_##name) {\
		free(discard_const(dyn_##name)); \
	}\
	dyn_##name = newpath; \
	return dyn_##name;\
}

DEFINE_DYN_CONFIG_PARAM(SBINDIR)
DEFINE_DYN_CONFIG_PARAM(BINDIR)
DEFINE_DYN_CONFIG_PARAM(CONFIGFILE) /**< Location of smb.conf file. **/
DEFINE_DYN_CONFIG_PARAM(LOGFILEBASE) /** Log file directory. **/
DEFINE_DYN_CONFIG_PARAM(LMHOSTSFILE) /** Statically configured LanMan hosts. **/
DEFINE_DYN_CONFIG_PARAM(CODEPAGEDIR)
DEFINE_DYN_CONFIG_PARAM(LIBDIR)
DEFINE_DYN_CONFIG_PARAM(MODULESDIR)
DEFINE_DYN_CONFIG_PARAM(SAMBA_LIBEXECDIR)
DEFINE_DYN_CONFIG_PARAM(SHLIBEXT)
DEFINE_DYN_CONFIG_PARAM(LOCKDIR)
DEFINE_DYN_CONFIG_PARAM(STATEDIR) /** Persistent state files. Default LOCKDIR */
DEFINE_DYN_CONFIG_PARAM(CACHEDIR) /** Temporary cache files. Default LOCKDIR */
DEFINE_DYN_CONFIG_PARAM(PIDDIR)
DEFINE_DYN_CONFIG_PARAM(NCALRPCDIR)
DEFINE_DYN_CONFIG_PARAM(SMB_PASSWD_FILE)
DEFINE_DYN_CONFIG_PARAM(PRIVATE_DIR)
DEFINE_DYN_CONFIG_PARAM(BINDDNS_DIR)
DEFINE_DYN_CONFIG_PARAM(LOCALEDIR)
DEFINE_DYN_CONFIG_PARAM(NMBDSOCKETDIR)
DEFINE_DYN_CONFIG_PARAM(DATADIR)
DEFINE_DYN_CONFIG_PARAM(SAMBA_DATADIR)
DEFINE_DYN_CONFIG_PARAM(SETUPDIR)
DEFINE_DYN_CONFIG_PARAM(WINBINDD_SOCKET_DIR) /* from winbind_struct_protocol.h in s3 autoconf */
DEFINE_DYN_CONFIG_PARAM(NTP_SIGND_SOCKET_DIR)
DEFINE_DYN_CONFIG_PARAM(PYTHONDIR)
DEFINE_DYN_CONFIG_PARAM(PYTHONARCHDIR)
DEFINE_DYN_CONFIG_PARAM(SCRIPTSBINDIR)

/* SambaDancer's relocatable macOS distribution paths.
 * Appended to Samba's dynconfig/dynconfig.c at build time.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifdef __APPLE__
#include <dlfcn.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void sambadancer_set_path(
    const char *base,
    const char *suffix,
    const char *(*setter)(const char *))
{
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s/%s", base, suffix);
    if (length > 0 && (size_t)length < sizeof(path)) {
        setter(path);
    }
}

static void __attribute__((constructor)) sambadancer_paths(void)
{
    Dl_info image;
    char root[PATH_MAX];
    char candidate[PATH_MAX];
    char settings[PATH_MAX];
    struct passwd *account;
    const char *home;
    const char *override;
    char *separator;
    int length;

    /* Locate the library itself, independent of cwd, PATH, and app location. */
    if (dladdr((const void *)&get_dyn_LIBDIR, &image) == 0 ||
        realpath(image.dli_fname, root) == NULL) {
        return;
    }
    for (;;) {
        separator = strrchr(root, '/');
        if (separator == NULL || separator == root) {
            return;
        }
        *separator = '\0';
        length = snprintf(candidate, sizeof(candidate), "%s/sbin/smbd", root);
        if (length > 0 && (size_t)length < sizeof(candidate) &&
            access(candidate, X_OK) == 0) {
            break;
        }
    }

    sambadancer_set_path(root, "bin", set_dyn_BINDIR);
    sambadancer_set_path(root, "sbin", set_dyn_SBINDIR);
    sambadancer_set_path(root, "sbin", set_dyn_SCRIPTSBINDIR);
    sambadancer_set_path(root, "lib", set_dyn_LIBDIR);
    sambadancer_set_path(root, "lib", set_dyn_MODULESDIR);
    sambadancer_set_path(root, "libexec/samba", set_dyn_SAMBA_LIBEXECDIR);
    sambadancer_set_path(root, "share", set_dyn_DATADIR);
    sambadancer_set_path(root, "share/samba", set_dyn_SAMBA_DATADIR);
    sambadancer_set_path(root, "share/codepages", set_dyn_CODEPAGEDIR);
    sambadancer_set_path(root, "share/locale", set_dyn_LOCALEDIR);

    /* The application states its storage directory explicitly. A server run
     * as root by the privileged helper, and the samba-dcerpcd it spawns, must
     * use the invoking user's directory rather than root's home. Absent the
     * variable, fall back to the process owner's home. */
    override = getenv("SAMBADANCER_STORAGE");
    if (override != NULL && override[0] == '/' && strlen(override) < sizeof(settings)) {
        snprintf(settings, sizeof(settings), "%s", override);
    } else {
        account = getpwuid(getuid());
        home = account != NULL ? account->pw_dir : NULL;
        if (home == NULL || home[0] != '/') {
            return;
        }
        length = snprintf(settings, sizeof(settings), "%s/.config/SambaDancer", home);
        if (length <= 0 || (size_t)length >= sizeof(settings)) {
            return;
        }
    }
    sambadancer_set_path(settings, "smb.conf", set_dyn_CONFIGFILE);
    sambadancer_set_path(settings, "lmhosts", set_dyn_LMHOSTSFILE);
    sambadancer_set_path(settings, "logs", set_dyn_LOGFILEBASE);
    sambadancer_set_path(settings, "private", set_dyn_PRIVATE_DIR);
    sambadancer_set_path(settings, "private/smbpasswd", set_dyn_SMB_PASSWD_FILE);
    sambadancer_set_path(settings, "state", set_dyn_STATEDIR);
    sambadancer_set_path(settings, "cache", set_dyn_CACHEDIR);
    sambadancer_set_path(settings, "run", set_dyn_LOCKDIR);
    sambadancer_set_path(settings, "run", set_dyn_PIDDIR);
    sambadancer_set_path(settings, "run/ncalrpc", set_dyn_NCALRPCDIR);
    sambadancer_set_path(settings, "run/nmbd", set_dyn_NMBDSOCKETDIR);
    sambadancer_set_path(settings, "run/winbindd", set_dyn_WINBINDD_SOCKET_DIR);
}
#endif
