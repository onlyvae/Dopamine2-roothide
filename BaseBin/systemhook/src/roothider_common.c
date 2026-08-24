#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/proc_info.h>
#include <dispatch/dispatch.h>

#include "roothider.h"

pid_t __getppid()
{
	int32_t opt[4] = {
		CTL_KERN,
		KERN_PROC,
		KERN_PROC_PID,
		getpid(),
	};
	struct kinfo_proc info={0};
	size_t len = sizeof(struct kinfo_proc);
	if(sysctl(opt, 4, &info, &len, NULL, 0) == 0) {
		if((info.kp_proc.p_flag & P_TRACED) != 0) {
			return info.kp_proc.p_oppid;
		}
	}

    struct proc_bsdinfo procInfo;
	//some process may be killed by sandbox if call systme getppid() so try this first
	if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) == sizeof(procInfo)) {
		return procInfo.pbi_ppid;
	}

	return getppid();
}

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
char* getAppUUIDPath(const char* path)
{
    if(!path) return NULL;

    char abspath[PATH_MAX];
    if(!realpath(path, abspath)) return NULL;

    if(strncmp(abspath, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return NULL;

    char* p1 = abspath + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return NULL;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return NULL;
	
	*p2 = '\0';

	return strdup(abspath);
}

bool isRemovableBundlePath(const char* path)
{
    const char* uuidpath = getAppUUIDPath(path);
	if(!uuidpath) return false;
	free((void*)uuidpath);
	return true;
}

bool hasTrollstoreMarker(const char* path)
{
    char* uuidpath = getAppUUIDPath(path);
	if(!uuidpath) return false;

	char* markerpath=NULL;
	asprintf(&markerpath, "%s/_TrollStore", uuidpath);

	int ret = access(markerpath, F_OK);
    if(ret != 0) {
        free((void*)markerpath); markerpath = NULL;
        asprintf(&markerpath, "%s/_TrollStoreLite", uuidpath);
        ret = access(markerpath, F_OK);
    }

    free((void*)markerpath);
	free((void*)uuidpath);

	return ret==0;
}

/* the only reason this function exists is to allow Choicy
	 to block systemhook injection for both stock daemons and normal apps (but not for their child processes) */
bool allowInjectWithSafeMode(const char* path)
{
	if(getpid() != 1) {
		return true;
	}

	if(isRemovableBundlePath(path))
	{
		if(hasTrollstoreMarker(path)) {
			//always inject into trollstored apps unless we blacklist it in roothide manager
			return true;
		} else {
			return false;
		}
	}

	struct statfs fs = {0};
	if(statfs(path, &fs) == 0) {
		if(strcmp(fs.f_mntonname, "/") == 0) {
			// disallow injecting into system process if Choicy blocked it
			return false;
		}
	}

	return true;
}


int __sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int syscall__sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) {
	return syscall(SYS_sysctl, name, namelen, oldp, oldlenp, newp, newlen);
}

#define BOOTSESSIONUUID_STRING_SIZE 37

static bool gIdentityRestoreConfigured = false;
static char gOriginalBootsessionUUID[BOOTSESSIONUUID_STRING_SIZE] = {0};
static struct timeval gOriginalBoottime = {0};

void sysctl_identity_restore_configure(const char *bootsessionuuid, uint64_t boottimeSeconds,
	uint32_t boottimeMicroseconds)
{
	if (!bootsessionuuid || strlen(bootsessionuuid) != BOOTSESSIONUUID_STRING_SIZE - 1 ||
		boottimeSeconds == 0 || boottimeMicroseconds >= 1000000) {
		return;
	}

	strlcpy(gOriginalBootsessionUUID, bootsessionuuid, sizeof(gOriginalBootsessionUUID));
	gOriginalBoottime.tv_sec = (time_t)boottimeSeconds;
	gOriginalBoottime.tv_usec = (suseconds_t)boottimeMicroseconds;
	gIdentityRestoreConfigured = true;
}

static bool sysctl_name_equals(const char *name, size_t namelen, const char *expected)
{
	return name && expected && namelen == strlen(expected) && memcmp(name, expected, namelen) == 0;
}

static bool sysctl_mib_equals(const int *name, u_int namelen, const int *expected, u_int expectedLength)
{
	return name && expected && namelen == expectedLength &&
		memcmp(name, expected, namelen * sizeof(name[0])) == 0;
}

static bool sysctl_restore_value(const void *value, size_t valueLength, void *oldp,
	size_t *oldlenp, const void *newp, size_t newlen, int *resultOut)
{
	if (!oldlenp || newp || newlen != 0) return false;

	size_t providedLength = *oldlenp;
	*oldlenp = valueLength;
	if (!oldp) {
		*resultOut = 0;
		return true;
	}
	if (providedLength < valueLength) {
		errno = ENOMEM;
		*resultOut = -1;
		return true;
	}

	memcpy(oldp, value, valueLength);
	*resultOut = 0;
	return true;
}

int __sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen)
{
	static int developerModeNameLength = 0;
	static int developerModeName[CTL_MAXNAME+2] = {0};
	static int bootsessionUUIDNameLength = 0;
	static int bootsessionUUIDName[CTL_MAXNAME+2] = {0};
	static int boottimeNameLength = 0;
	static int boottimeName[CTL_MAXNAME+2] = {0};

	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		int mib[] = {0, 3}; //https://github.com/apple-oss-distributions/Libc/blob/899a3b2d52d95d75e05fb286a5e64975ec3de757/gen/FreeBSD/sysctlbyname.c#L24
		size_t buflen = 0;
		if (__builtin_available(iOS 16.0, *)) {
			buflen = sizeof(developerModeName);
			const char *query = "security.mac.amfi.developer_mode_status";
			if (syscall__sysctl(mib, 2, developerModeName, &buflen, query, strlen(query)) == 0) {
				developerModeNameLength = (int)(buflen / sizeof(developerModeName[0]));
			}
		}

		buflen = sizeof(bootsessionUUIDName);
		const char *uuidQuery = "kern.bootsessionuuid";
		if (syscall__sysctl(mib, 2, bootsessionUUIDName, &buflen, uuidQuery, strlen(uuidQuery)) == 0) {
			bootsessionUUIDNameLength = (int)(buflen / sizeof(bootsessionUUIDName[0]));
		}

		buflen = sizeof(boottimeName);
		const char *boottimeQuery = "kern.boottime";
		if (syscall__sysctl(mib, 2, boottimeName, &buflen, boottimeQuery, strlen(boottimeQuery)) == 0) {
			boottimeNameLength = (int)(buflen / sizeof(boottimeName[0]));
		}
	});

	if (developerModeNameLength &&
		sysctl_mib_equals(name, namelen, developerModeName, developerModeNameLength)) {
		if(oldp && oldlenp && *oldlenp>=sizeof(int)) {
			*(int*)oldp = 1;
			*oldlenp = sizeof(int);
			return 0;
		}
	}

	if (gIdentityRestoreConfigured) {
		int result = 0;
		if (bootsessionUUIDNameLength &&
			sysctl_mib_equals(name, namelen, bootsessionUUIDName, bootsessionUUIDNameLength) &&
			sysctl_restore_value(gOriginalBootsessionUUID, sizeof(gOriginalBootsessionUUID), oldp,
				oldlenp, newp, newlen, &result)) {
			return result;
		}
		if (boottimeNameLength &&
			sysctl_mib_equals(name, namelen, boottimeName, boottimeNameLength) &&
			sysctl_restore_value(&gOriginalBoottime, sizeof(gOriginalBoottime), oldp,
				oldlenp, newp, newlen, &result)) {
			return result;
		}
	}

	return syscall__sysctl(name,namelen,oldp,oldlenp,newp,newlen);
}

int __sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int syscall__sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	return syscall(SYS_sysctlbyname, name, namelen, oldp, oldlenp, newp, newlen);
}
int __sysctlbyname_hook(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	if (__builtin_available(iOS 16.0, *)) {
		if (sysctl_name_equals(name, namelen, "security.mac.amfi.developer_mode_status")) {
			if(oldp && oldlenp && *oldlenp>=sizeof(int)) {
				*(int*)oldp = 1;
				*oldlenp = sizeof(int);
				return 0;
			}
		}
	}

	if (gIdentityRestoreConfigured) {
		int result = 0;
		if (sysctl_name_equals(name, namelen, "kern.bootsessionuuid") &&
			sysctl_restore_value(gOriginalBootsessionUUID, sizeof(gOriginalBootsessionUUID), oldp,
				oldlenp, newp, newlen, &result)) {
			return result;
		}
		if (sysctl_name_equals(name, namelen, "kern.boottime") &&
			sysctl_restore_value(&gOriginalBoottime, sizeof(gOriginalBoottime), oldp,
				oldlenp, newp, newlen, &result)) {
			return result;
		}
	}

	return syscall__sysctlbyname(name,namelen,oldp,oldlenp,newp,newlen);
}
