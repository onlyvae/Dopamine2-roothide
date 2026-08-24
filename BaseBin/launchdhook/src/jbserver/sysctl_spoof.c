#include "sysctl_spoof.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libjailbreak/jbroot.h>

#define SYSCTL_SPOOF_STATE_MAGIC 0x53595343544C4944ULL
#define SYSCTL_SPOOF_STATE_VERSION 1
#define SYSCTL_SPOOF_STATE_PATH "/var/.sysctl-identity-state"

struct sysctl_spoof_state {
	uint64_t magic;
	uint32_t version;
	uint32_t reserved;
	char originalBootsessionUUID[BOOTSESSIONUUID_STRING_SIZE];
	char installedBootsessionUUID[BOOTSESSIONUUID_STRING_SIZE];
	uint64_t originalBoottimeSeconds;
	uint32_t originalBoottimeMicroseconds;
	uint32_t reserved2;
	uint64_t installedBoottimeSeconds;
	uint32_t installedBoottimeMicroseconds;
	uint32_t reserved3;
};

static pthread_mutex_t gSysctlSpoofLock = PTHREAD_MUTEX_INITIALIZER;
static bool gSysctlSpoofInitialized = false;
static struct sysctl_spoof_state gSysctlSpoofState = {0};

static int sysctl_spoof_state_read(struct sysctl_spoof_state *stateOut)
{
	const char *path = JBROOT_PATH(SYSCTL_SPOOF_STATE_PATH);
	if (!path || !stateOut) return EINVAL;

	int fd = open(path, O_RDONLY);
	if (fd < 0) return errno;
	struct sysctl_spoof_state state = {0};
	ssize_t bytesRead = read(fd, &state, sizeof(state));
	int savedErrno = errno;
	close(fd);
	if (bytesRead != sizeof(state)) return bytesRead < 0 ? savedErrno : EIO;
	if (state.magic != SYSCTL_SPOOF_STATE_MAGIC ||
		state.version != SYSCTL_SPOOF_STATE_VERSION ||
		state.originalBootsessionUUID[BOOTSESSIONUUID_STRING_SIZE - 1] != '\0' ||
		state.installedBootsessionUUID[BOOTSESSIONUUID_STRING_SIZE - 1] != '\0' ||
		state.originalBoottimeSeconds == 0 || state.originalBoottimeMicroseconds >= 1000000) {
		return EPROTO;
	}

	*stateOut = state;
	return 0;
}

static int sysctl_spoof_state_write(const struct sysctl_spoof_state *state)
{
	const char *path = JBROOT_PATH(SYSCTL_SPOOF_STATE_PATH);
	if (!path || !state) return EINVAL;
	char temporaryPath[PATH_MAX] = {0};
	if (snprintf(temporaryPath, sizeof(temporaryPath), "%s.tmp", path) >= sizeof(temporaryPath)) return ENAMETOOLONG;

	int fd = open(temporaryPath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) return errno;
	ssize_t bytesWritten = write(fd, state, sizeof(*state));
	int result = 0;
	if (bytesWritten != sizeof(*state) || fsync(fd) != 0) result = errno ? errno : EIO;
	if (close(fd) != 0 && result == 0) result = errno;
	if (result == 0 && rename(temporaryPath, path) != 0) result = errno;
	if (result != 0) unlink(temporaryPath);
	return result;
}

static int sysctl_spoof_init_locked(void)
{
	if (gSysctlSpoofInitialized) return 0;

	char currentUUID[BOOTSESSIONUUID_STRING_SIZE] = {0};
	uint64_t currentSeconds = 0;
	uint32_t currentMicroseconds = 0;
	int r = bootsessionuuid_get(currentUUID);
	if (r != 0) return r;
	r = boottime_get(&currentSeconds, &currentMicroseconds);
	if (r != 0) return r;

	struct sysctl_spoof_state persisted = {0};
	if (sysctl_spoof_state_read(&persisted) == 0 &&
		(strcmp(currentUUID, persisted.originalBootsessionUUID) == 0 ||
		 strcmp(currentUUID, persisted.installedBootsessionUUID) == 0)) {
		gSysctlSpoofState = persisted;
	}
	else {
		gSysctlSpoofState.magic = SYSCTL_SPOOF_STATE_MAGIC;
		gSysctlSpoofState.version = SYSCTL_SPOOF_STATE_VERSION;
		memcpy(gSysctlSpoofState.originalBootsessionUUID, currentUUID, sizeof(currentUUID));
		memcpy(gSysctlSpoofState.installedBootsessionUUID, currentUUID, sizeof(currentUUID));
		gSysctlSpoofState.originalBoottimeSeconds = currentSeconds;
		gSysctlSpoofState.originalBoottimeMicroseconds = currentMicroseconds;
		gSysctlSpoofState.installedBoottimeSeconds = currentSeconds;
		gSysctlSpoofState.installedBoottimeMicroseconds = currentMicroseconds;
		r = sysctl_spoof_state_write(&gSysctlSpoofState);
		if (r != 0) return r;
	}

	gSysctlSpoofInitialized = true;
	return 0;
}

int sysctl_spoof_init(void)
{
	pthread_mutex_lock(&gSysctlSpoofLock);
	int r = sysctl_spoof_init_locked();
	pthread_mutex_unlock(&gSysctlSpoofLock);
	return r;
}

int sysctl_spoof_get_originals(char uuidOut[BOOTSESSIONUUID_STRING_SIZE],
	uint64_t *secondsOut, uint32_t *microsecondsOut)
{
	pthread_mutex_lock(&gSysctlSpoofLock);
	int r = sysctl_spoof_init_locked();
	if (r == 0) {
		if (uuidOut) memcpy(uuidOut, gSysctlSpoofState.originalBootsessionUUID,
			sizeof(gSysctlSpoofState.originalBootsessionUUID));
		if (secondsOut) *secondsOut = gSysctlSpoofState.originalBoottimeSeconds;
		if (microsecondsOut) *microsecondsOut = gSysctlSpoofState.originalBoottimeMicroseconds;
	}
	pthread_mutex_unlock(&gSysctlSpoofLock);
	return r;
}

int sysctl_spoof_bootsessionuuid_set(const char *uuid)
{
	pthread_mutex_lock(&gSysctlSpoofLock);
	int r = sysctl_spoof_init_locked();
	char previous[BOOTSESSIONUUID_STRING_SIZE] = {0};
	char installed[BOOTSESSIONUUID_STRING_SIZE] = {0};
	if (r == 0) r = bootsessionuuid_get(previous);
	if (r == 0) r = bootsessionuuid_set(uuid);
	if (r == 0) {
		r = bootsessionuuid_get(installed);
		if (r != 0) bootsessionuuid_set(previous);
	}
	if (r == 0) {
		char oldInstalled[BOOTSESSIONUUID_STRING_SIZE] = {0};
		memcpy(oldInstalled, gSysctlSpoofState.installedBootsessionUUID, sizeof(oldInstalled));
		strlcpy(gSysctlSpoofState.installedBootsessionUUID, installed,
			sizeof(gSysctlSpoofState.installedBootsessionUUID));
		r = sysctl_spoof_state_write(&gSysctlSpoofState);
		if (r != 0) {
			bootsessionuuid_set(previous);
			memcpy(gSysctlSpoofState.installedBootsessionUUID, oldInstalled, sizeof(oldInstalled));
		}
	}
	pthread_mutex_unlock(&gSysctlSpoofLock);
	return r;
}

int sysctl_spoof_boottime_set(uint64_t seconds, uint32_t microseconds)
{
	pthread_mutex_lock(&gSysctlSpoofLock);
	int r = sysctl_spoof_init_locked();
	uint64_t previousSeconds = 0;
	uint32_t previousMicroseconds = 0;
	if (r == 0) r = boottime_get(&previousSeconds, &previousMicroseconds);
	if (r == 0) r = boottime_set(seconds, microseconds);
	if (r == 0) {
		uint64_t oldInstalledSeconds = gSysctlSpoofState.installedBoottimeSeconds;
		uint32_t oldInstalledMicroseconds = gSysctlSpoofState.installedBoottimeMicroseconds;
		gSysctlSpoofState.installedBoottimeSeconds = seconds;
		gSysctlSpoofState.installedBoottimeMicroseconds = microseconds;
		r = sysctl_spoof_state_write(&gSysctlSpoofState);
		if (r != 0) {
			boottime_set(previousSeconds, previousMicroseconds);
			gSysctlSpoofState.installedBoottimeSeconds = oldInstalledSeconds;
			gSysctlSpoofState.installedBoottimeMicroseconds = oldInstalledMicroseconds;
		}
	}
	pthread_mutex_unlock(&gSysctlSpoofLock);
	return r;
}
