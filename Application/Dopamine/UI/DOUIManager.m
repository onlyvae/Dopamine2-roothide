//
//  DOUIManager.m
//  Dopamine
//
//  Created by tomt000 on 24/01/2024.
//

#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import "DOThemeManager.h"
#import "DOTheme.h"
#import "NSString+Version.h"
#import <errno.h>
#import <fcntl.h>
#import <pthread.h>
#import <unistd.h>

@implementation DOUIManager

+ (instancetype)sharedInstance
{
    static DOUIManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[DOUIManager alloc] init];
    });
    return sharedInstance;
}

- (id)init
{
    if (self = [super init]){
        _bootlogoPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/bootlogo.png"];
        _logFilePath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/dopamine-latest.log"];
        _preferenceManager = [DOPreferenceManager sharedManager];
        _logRecord = [NSMutableArray new];
        _logLock = [NSLock new];
        _logFileLock = [NSLock new];
        _logFileDescriptor = -1;
        _logCaptureStarted = NO;
    }
    return self;
}

- (void)resetPersistentLog
{
    [_logFileLock lock];

    if (_logFileDescriptor >= 0) {
        close(_logFileDescriptor);
        _logFileDescriptor = -1;
    }

    _logFileDescriptor = open(self.logFilePath.fileSystemRepresentation,
                              O_WRONLY | O_CREAT | O_TRUNC | O_APPEND,
                              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    if (_logFileDescriptor >= 0) {
        NSString *header = [NSString stringWithFormat:
                            @"Dopamine %@ persistent log\nStarted: %@\n\n",
                            [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"unknown",
                            [NSDate date]];
        NSData *headerData = [header dataUsingEncoding:NSUTF8StringEncoding];
        const uint8_t *bytes = headerData.bytes;
        NSUInteger remaining = headerData.length;
        while (remaining > 0) {
            ssize_t written = write(_logFileDescriptor, bytes, remaining);
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                break;
            }
            bytes += written;
            remaining -= written;
        }
    }

    [_logFileLock unlock];
}

- (void)appendLogToFile:(NSString *)log
{
    if (!log) return;

    NSData *logData = [log dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    if (!logData) return;

    [_logFileLock lock];
    if (_logFileDescriptor >= 0) {
        const uint8_t *bytes = logData.bytes;
        NSUInteger remaining = logData.length;
        while (remaining > 0) {
            ssize_t written = write(_logFileDescriptor, bytes, remaining);
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                break;
            }
            bytes += written;
            remaining -= written;
        }

        if (![log hasSuffix:@"\n"]) {
            const char newline = '\n';
            write(_logFileDescriptor, &newline, sizeof(newline));
        }
    }
    [_logFileLock unlock];
}

- (BOOL)isUpdateAvailable
{
    NSString *latestVersion = [self getLatestReleaseTag];
    NSString *currentVersion = [self getLaunchedReleaseTag];
    return [latestVersion numericalVersionRepresentation] > [currentVersion numericalVersionRepresentation];
}

- (NSArray *)getUpdatesInRange:(NSString *)start end:(NSString *)end
{
    NSArray *releases = [self getLatestReleases];
    if (releases.count == 0)
        return @[];

    long long startVersion = [start numericalVersionRepresentation];
    long long endVersion = [end numericalVersionRepresentation];
    NSMutableArray *updates = [NSMutableArray new];
    for (NSDictionary *release in releases) {
        NSString *version = release[@"tag_name"];
        NSNumber *prerelease = release[@"prerelease"];
        if ([prerelease boolValue]) {
            // Skip prereleases
            continue;
        }
        long long numericalVersion = [version numericalVersionRepresentation];
        if (numericalVersion > startVersion && numericalVersion <= endVersion) {
            [updates addObject:release];
        }
    }
    return updates;
}

- (NSArray *)getLatestReleases
{
    static dispatch_once_t onceToken;
    static NSArray *releases;
    dispatch_once(&onceToken, ^{
        NSURL *url = [NSURL URLWithString:@"https://api.github.com/repos/roothide/Dopamine2-roothide/releases"];
        NSData *data = [NSData dataWithContentsOfURL:url];
        if (data) {
            NSError *error;
            releases = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:&error];
            if (error)
            {
                onceToken = 0;
                releases = @[];
            }
        }
    });
    return releases;
}

- (BOOL)environmentUpdateAvailable
{
    if (![[DOEnvironmentManager sharedManager] jailbrokenVersion])
        return NO;

    NSString *jailbrokenVersion = [[DOEnvironmentManager sharedManager] jailbrokenVersion];
    NSString *launchedVersion = [self getLaunchedReleaseTag];
    
    return [launchedVersion numericalVersionRepresentation] > [jailbrokenVersion numericalVersionRepresentation];
}

- (bool)launchedReleaseNeedsManualUpdate
{
    NSString *launchedTag = [self getLaunchedReleaseTag];
    NSDictionary *launchedVersion;
    for (NSDictionary *release in [self getLatestReleases]) {
        if ([release[@"tag_name"] isEqualToString:launchedTag]) {
            launchedVersion = release;
            break;
        }
    }
    if (!launchedVersion)
        return false;
    return [launchedVersion[@"body"] containsString:@"*Manual Updates*"];
}

- (NSString*)getLatestReleaseTag
{
    NSArray *releases = [self getLatestReleases];
    for (NSDictionary *release in releases) {
        NSNumber *prerelease = release[@"prerelease"];
        if ([prerelease boolValue]) {
            continue;
        }
        return release[@"tag_name"];
    }
    return nil;
}

- (NSString*)getLaunchedReleaseTag
{
    return [[[[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] componentsSeparatedByString:@"."] lastObject];
}

- (NSArray*)availablePackageManagers
{
    NSString *path = [[NSBundle mainBundle] pathForResource:@"PkgManagers" ofType:@"plist"];
    return [NSArray arrayWithContentsOfFile:path];
}

- (NSArray*)enabledPackageManagerKeys
{
    NSArray *enabledPkgManagers = [_preferenceManager preferenceValueForKey:@"enabledPkgManagers"] ?: @[];
    NSMutableArray *enabledKeys = [NSMutableArray new];
    NSArray *availablePkgManagers = [self availablePackageManagers];

    [availablePkgManagers enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString *key = obj[@"Key"];
        if ([enabledPkgManagers containsObject:key]) {
            [enabledKeys addObject:key];
        }
    }];

    return enabledKeys;
}

- (NSArray*)enabledPackageManagers
{
    NSMutableArray *enabledPkgManagers = [NSMutableArray new];
    NSArray *enabledKeys = [self enabledPackageManagerKeys];

    [[self availablePackageManagers] enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString *key = obj[@"Key"];
        if ([enabledKeys containsObject:key]) {
            [enabledPkgManagers addObject:obj];
        }
    }];

    return enabledPkgManagers;
}

- (void)resetPackageManagers
{
    [_preferenceManager removePreferenceValueForKey:@"enabledPkgManagers"];
}

- (void)resetSettings
{
    [_preferenceManager removePreferenceValueForKey:@"verboseLogsEnabled"];
    [_preferenceManager removePreferenceValueForKey:@"tweakInjectionEnabled"];
    [self resetPackageManagers];
}

- (void)setPackageManager:(NSString*)key enabled:(BOOL)enabled
{
    NSMutableArray *pkgManagers = [self enabledPackageManagerKeys].mutableCopy;
    
    if (enabled && ![pkgManagers containsObject:key]) {
        [pkgManagers addObject:key];
    }
    else if (!enabled && [pkgManagers containsObject:key]) {
        [pkgManagers removeObject:key];
    }

    [_preferenceManager setPreferenceValue:pkgManagers forKey:@"enabledPkgManagers"];
}

- (BOOL)isDebug
{
    NSNumber *debug = [_preferenceManager preferenceValueForKey:@"verboseLogsEnabled"];
    return debug == nil ? NO : [debug boolValue];
}

- (BOOL)enableTweaks
{
    NSNumber *tweaks = [_preferenceManager preferenceValueForKey:@"tweakInjectionEnabled"];
    return tweaks == nil ? YES : [tweaks boolValue];
}

- (void)sendLog:(NSString*)log debug:(BOOL)debug update:(BOOL)update
{
    if (!log)
        return;

    [self appendLogToFile:log];

    if (!self.logView)
        return;

    [_logLock lock];

    [self.logRecord addObject:log];

    BOOL isDebug = self.logView.class == DODebugLogView.class;
    if (debug && !isDebug) {
        [_logLock unlock];
        return;
    }
        
    
    if (update) {
        if ([self.logView respondsToSelector:@selector(updateLog:)]) {
            [self.logView updateLog:log];
        }
    }
    else {
        [self.logView showLog:log];
    }
    [_logLock unlock];
}

- (void)sendLog:(NSString*)log debug:(BOOL)debug
{
    [self sendLog:log debug:debug update:NO];
}

- (void)shareLogRecordFromView:(UIView *)sourceView
{
    id activityItem = nil;
    if ([[NSFileManager defaultManager] fileExistsAtPath:self.logFilePath]) {
        activityItem = [NSURL fileURLWithPath:self.logFilePath];
    }
    else if (self.logRecord.count > 0) {
        activityItem = [self.logRecord componentsJoinedByString:@"\n"];
    }
    if (!activityItem) return;

    UIActivityViewController *activityViewController = [[UIActivityViewController alloc] initWithActivityItems:@[activityItem] applicationActivities:nil];
    activityViewController.popoverPresentationController.sourceView = sourceView;
    activityViewController.popoverPresentationController.sourceRect = sourceView.bounds;
    [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:activityViewController animated:YES completion:nil];
}

- (void)completeJailbreak
{
    if (!self.logView)
        return;

    [self.logView didComplete];
}

- (void)observeFileDescriptor:(int)fd withCallback:(void (^)(char *line))callbackBlock
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int stdout_pipe[2];
        int stdout_orig[2];
        if (pipe(stdout_pipe) != 0 || pipe(stdout_orig) != 0) {
            return;
        }

        dup2(fd, stdout_orig[1]);
        close(stdout_orig[0]);
        
        dup2(stdout_pipe[1], fd);
        close(stdout_pipe[1]);
        
        char cur = 0;
        char line[1024];
        int line_index = 0;
        ssize_t bytes_read;

        while ((bytes_read = read(stdout_pipe[0], &cur, sizeof(cur))) > 0) {
            @autoreleasepool {
                write(stdout_orig[1], &cur, bytes_read);

                if (cur == '\n') {
                    line[line_index] = '\0';
                    callbackBlock(line);
                    line_index = 0;
                } else {
                    if (line_index < sizeof(line) - 1) {
                        line[line_index++] = cur;
                    }
                }
            }
        }
        close(stdout_pipe[0]);
    });
}

- (void)startLogCapture
{
    [self resetPersistentLog];

    // Keep printf output out of stdio buffers so assertion details reach disk
    // before libkfd deliberately terminates the process.
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (_logCaptureStarted) return;
    _logCaptureStarted = YES;

    [self observeFileDescriptor:STDOUT_FILENO withCallback:^(char *line) {
        NSString *str = [NSString stringWithUTF8String:line];
        [self sendLog:str debug:YES];
    }];
    
    [self observeFileDescriptor:STDERR_FILENO withCallback:^(char *line) {
        NSString *str = [NSString stringWithUTF8String:line];
        [self sendLog:str debug:YES];
    }];
}

- (NSString *)localizedStringForKey:(NSString*)key
{
    NSString *candidate = NSLocalizedString(key, nil);
    if ([candidate isEqualToString:key]) {
        if (!_fallbackLocalizations) {
            _fallbackLocalizations = [NSDictionary dictionaryWithContentsOfFile:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"en.lproj/Localizable.strings"]];
        }
        candidate = _fallbackLocalizations[key];
        if (!candidate) candidate = key;
    }
    return candidate;
}

- (UIImage *)renderBootLogo
{
    return [[[DOThemeManager sharedInstance] enabledTheme] generateBootLogo];
}

@end


NSString *DOLocalizedString(NSString *key)
{
    return [[DOUIManager sharedInstance] localizedStringForKey:key];
}
