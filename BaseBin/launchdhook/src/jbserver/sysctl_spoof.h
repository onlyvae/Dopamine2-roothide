#ifndef SYSCTL_SPOOF_H
#define SYSCTL_SPOOF_H

#include <stdbool.h>
#include <stdint.h>
#include <libjailbreak/roothider.h>

int sysctl_spoof_init(void);
int sysctl_spoof_get_originals(char uuidOut[BOOTSESSIONUUID_STRING_SIZE],
    uint64_t *secondsOut, uint32_t *microsecondsOut);
int sysctl_spoof_bootsessionuuid_set(const char *uuid);
int sysctl_spoof_boottime_set(uint64_t seconds, uint32_t microseconds);

#endif
