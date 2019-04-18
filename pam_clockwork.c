/* BSD 2-Clause License
 * 
 * Copyright (c) 2018, jwkblades
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/* The following defined must be present _before_ pam is included, according to its documentation. */
#define PAM_SM_AUTH

#include <security/pam_modules.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif

#define UNUSED __attribute__((unused))

#define VERSION "0.2"
#define TEMPORARY_PATH "/tmp/"
#define CACHEFILE_SUFFIX ".clockwork"
#define MODULE_LOCATION "/lib/security/"

#define DEFAULT_TIMEOUT_SECONDS 60

struct clockworkConfig
{
    int             debug;
    int             alwaysOk;
    int             timeoutSeconds;
    const char*     subModule;
    int             subArgc;
    const char**    subArgv;
    FILE*           debugFile;
    FILE*           cacheFile;
    char*           callingUser;
    const char*     destinationUser;
    char*           effectiveUser;
};

#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG(...)                          \
if (cfg->debug)                             \
{                                           \
    fprintf(cfg->debugFile, __VA_ARGS__);   \
    fprintf(cfg->debugFile, "\n");          \
}

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

static int doStringsMatch(const char* a, const char* b)
{
    int lengthA = strlen(a);
    int lengthB = strlen(b);

    return lengthA == lengthB &&
        strncmp(a, b, lengthA) == 0;
}

static int isPrefixedBy(const char* a, const char* b)
{
    int lengthA = strlen(a);
    int lengthB = strlen(b);

    return lengthA >= lengthB &&
        strncmp(a, b, MIN(lengthA, lengthB)) == 0;
}

static void parseConfig(int flags, int argc, const char** argv, struct clockworkConfig* cfg)
{
    int i = 0;

    memset(cfg, 0, sizeof(struct clockworkConfig));
    cfg->timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
    cfg->debugFile = stdout;

    for(; i < argc; ++i)
    {
        if (doStringsMatch(argv[i], "debug"))
        {
            cfg->debug = 1;
        }
        else if (doStringsMatch(argv[i], "alwaysok"))
        {
            cfg->alwaysOk = 1;
        }
        else if (isPrefixedBy(argv[i], "timeout="))
        {
            sscanf(argv[i], "timeout=%d", &cfg->timeoutSeconds);
        }
        else if (isPrefixedBy(argv[i], "debug_file="))
        {
            const char* filename = argv[i] + 11;
            if (doStringsMatch(filename, "stdout"))
            {
                cfg->debugFile = stdout;
            }
            else if (doStringsMatch(filename, "stderr"))
            {
                cfg->debugFile = stderr;
            }
            else
            {
                struct stat st;
                int fd;
                FILE* file;
                if (lstat(filename, &st) == 0)
                {
                    if (S_ISREG(st.st_mode))
                    {
                        fd = open(filename, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP);
                        if (fd >= 0)
                        {
                            file = fdopen(fd, "a");
                            if (file)
                            {
                                cfg->debugFile = file;
                            }
                            else
                            {
                                close(fd);
                            }
                        }
                    }
                }
            }
        }
        else if (doStringsMatch(argv[i], "--"))
        {
            if (i + 1 < argc)
            {
                cfg->subModule = argv[i + 1];
                cfg->subArgc = argc - (i + 2);
                if (cfg->subArgc > 0)
                {
                    cfg->subArgv = argv + (i + 2);
                }
            }
        }
    }

    DEBUG("PAM_CLOCKWORK called.");
    DEBUG("flags %d argc %d", flags, argc);
    for (i = 0; i < argc; ++i)
    {
        DEBUG("argv[%d]=%s", i, argv[i]);
    }
    DEBUG("debug=%d", cfg->debug);
    DEBUG("debug_file=%d", fileno(cfg->debugFile));
    DEBUG("alwaysok=%d", cfg->alwaysOk);
    DEBUG("timeout=%d", cfg->timeoutSeconds);
    DEBUG("module=%s", cfg->subModule);
    DEBUG("    argc %d", cfg->subArgc);
    for (i = 0; i < cfg->subArgc; ++i)
    {
        DEBUG("    argv[%d]=%s", i, cfg->subArgv[i]);
    }
}

int usernameFromUid(struct passwd* userInfo, char** destination)
{
    if (!userInfo)
    {
        return PAM_CONV_ERR;
    }

    if (*destination)
    {
        free(*destination);
        (*destination) = NULL;
    }

    int retval = PAM_SUCCESS;
    int usernameLen = strlen(userInfo->pw_name);

    (*destination) = (char*) malloc(usernameLen + 1);

    if (destination)
    {
        strncpy(*destination, userInfo->pw_name, usernameLen);
        (*destination)[usernameLen] = '\0';
    }
    else
    {
        retval = PAM_CONV_ERR;
    }

    return retval;
}

int getUsernames(pam_handle_t* pamHandle, struct clockworkConfig* cfg)
{
    int retval = pam_get_user(pamHandle, &cfg->destinationUser, NULL);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }
    DEBUG("Destination user: %s", cfg->destinationUser);

    uid_t callingUID = getuid();
    uid_t effectiveUID = geteuid();

    struct passwd* userInfo = getpwuid(callingUID);
    retval = usernameFromUid(userInfo, &cfg->callingUser);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }
    DEBUG("Calling user: %s", cfg->callingUser);

    userInfo = getpwuid(effectiveUID);
    retval = usernameFromUid(userInfo, &cfg->effectiveUser);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    DEBUG("Effective user: %s", cfg->effectiveUser);
    return retval;
}

void* isModuleLoaded(struct clockworkConfig* cfg, const char* modulePathAndName)
{
    void* handle = NULL;

    if (!modulePathAndName)
    {
        DEBUG("No module path set.");
        return NULL;
    }

    handle = dlopen(modulePathAndName, RTLD_NOW | RTLD_NOLOAD);
    return handle;
}

int moduleUnload(void* module)
{
    if (!module)
    {
        return 0;
    }
    return dlclose(module);
}

void* moduleLoad(struct clockworkConfig* cfg, const char* modulePathAndName)
{
    void* module = NULL;

    if (!modulePathAndName)
    {
        DEBUG("No module path set.");
        return NULL;
    }

    module = isModuleLoaded(cfg, modulePathAndName);
    if (module)
    {
        moduleUnload(module);
    }

    DEBUG("Loading the module %s", modulePathAndName);
    module = dlopen(modulePathAndName, RTLD_NOW);

    if (!module)
    {
        DEBUG("Module load failed with %s", dlerror());
    }

    return module;
}

char* stringConcat(int argc, const char** argv)
{
    int i;
    int bufferSize = 1; /* To account for the null-termination byte */
    int offset = 0;
    char* buffer = NULL;

    for (i = 0; i < argc; ++i)
    {
        bufferSize += strlen(argv[i]);
    }

    buffer = malloc(bufferSize);

    for (i = 0; i < argc; ++i)
    {
        strcpy(buffer + offset, argv[i]); 
        offset += strlen(argv[i]);
    }

    buffer[bufferSize - 1] = '\0';
    return buffer;
}

int finalize(pam_handle_t* pamHandle, struct clockworkConfig* cfg, char* modulePathAndName, void* module, int retval)
{
    if (cfg->alwaysOk && retval != PAM_SUCCESS)
    {
        DEBUG("alwaysok set (otherwise, would return with %d)", retval);
        retval = PAM_SUCCESS;
    }
    DEBUG("Done. [%s]", pam_strerror(pamHandle, retval));

    if (modulePathAndName)
    {
        free(modulePathAndName);
    }

    moduleUnload(module);

    pam_set_data(pamHandle, "clockwork_setcred_return", (void*)(intptr_t)retval, NULL);

    if (cfg->debugFile != stderr && cfg->debugFile != stdout)
    {
        fclose(cfg->debugFile);
    }

    if (cfg->cacheFile)
    {
        fclose(cfg->cacheFile);
    }

    if (cfg->callingUser)
    {
        free(cfg->callingUser);
    }

    if (cfg->effectiveUser)
    {
        free(cfg->effectiveUser);
    }

    return retval;
}

int cachedAuth(struct clockworkConfig* cfg, const char* user, const char* module)
{
    int timestamp = time(NULL) - cfg->timeoutSeconds;
    const char* parts[] = {TEMPORARY_PATH, user, CACHEFILE_SUFFIX};
    char* filename = stringConcat(3, parts);

    struct stat st;
    int fd;
    FILE* file;
    ssize_t read;
    char* line = NULL;
    size_t len = 0;
    int cacheTime;
    int retval = PAM_AUTHINFO_UNAVAIL;

    DEBUG("Searching cache file at %s for module %s; current time = %d", filename, module, timestamp);
    if (lstat(filename, &st) == 0)
    {
        if (S_ISREG(st.st_mode))
        {
            fd = open(filename, O_RDONLY | O_CLOEXEC);
            if (fd >= 0)
            {
                file = fdopen(fd, "r");
                if (!file)
                {
                    close(fd);
                    free(filename);
                    DEBUG("No cache file found.");
                    return PAM_AUTHINFO_UNAVAIL;
                }
            }
        }
    }
    else
    {
        free(filename);
        return PAM_AUTHINFO_UNAVAIL;
    }
    free(filename);
    filename = NULL;

    if (file == NULL)
    {
        DEBUG("Cache file doesn't exist.");
        return PAM_AUTHINFO_UNAVAIL;
    }

    DEBUG("Cache file located successfully.");
    while ((read = getline(&line, &len, file)) != -1)
    {
        DEBUG("Read line '%s'", line);
        if (doStringsMatch(line, module))
        {
            const char* lineParts[] = {module, ",%d,%d"};
            char* expectedLine = stringConcat(2, lineParts);

            sscanf(line, expectedLine, &cacheTime, &retval);

            DEBUG("Expecing line '%s', to get cachetime = %d and retval = %d", expectedLine, cacheTime, retval);

            free(expectedLine);
            
            if (timestamp < cacheTime)
            {
                break;
            }
        }
        retval = PAM_AUTHINFO_UNAVAIL;
    }

    if (line)
    {
        free(line);
    }
    close(fd);

    return retval;
}

void cacheResult(struct clockworkConfig* cfg, const char* user, const char* module, int retval)
{
    const char* parts[] = {TEMPORARY_PATH, user, CACHEFILE_SUFFIX};
    char* filename = stringConcat(3, parts);
    int timestamp = time(NULL);
    int fd;

    DEBUG("Writing cached result %d for %s to %s.", retval, module, filename);
    fd = open(filename, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd >= 0)
    {
        DEBUG("Caching line %s,%d,%d to %s", module, timestamp, retval, filename);
        int written = dprintf(fd, "%s,%d,%d\n", module, timestamp, retval);
        DEBUG("Wrote %d bytes to cache.", written);

        if (written < 0)
        {
            DEBUG("Unable to write to cache file!");
        }

        fsync(fd);
        close(fd);
    }
    else
    {
        DEBUG("Unable to open cache file.");
    }
}

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t* pamHandle, int flags, int argc, const char** argv)
{
    int retval;
    struct clockworkConfig cfgInstance;
    struct clockworkConfig* cfg = &cfgInstance;
    void* module = NULL;
    char* modulePathAndName = NULL;
    int (*moduleAuthFunc)(pam_handle_t*, int, int, const char**);

    parseConfig(flags, argc, argv, cfg);

    DEBUG("pam_clockwork version: %s", VERSION);

    retval = getUsernames(pamHandle, cfg);
    if (retval != PAM_SUCCESS)
    {
        DEBUG("Get user returned error: %s", pam_strerror(pamHandle, retval));
        return finalize(pamHandle, cfg, modulePathAndName, module, retval);
    }

    retval = cachedAuth(cfg, cfg->callingUser, cfg->subModule);
    if (retval == PAM_SUCCESS || retval == PAM_MAXTRIES)
    {
        DEBUG("Authentication cached.");
        return finalize(pamHandle, cfg, modulePathAndName, module, retval);
    }

    const char* parts[] = {MODULE_LOCATION, cfg->subModule};
    modulePathAndName = stringConcat(2, parts);
    module = moduleLoad(cfg, modulePathAndName);

    if (!module)
    {
        DEBUG("Unable to load module %s, returning auth erro.", cfg->subModule);
        return finalize(pamHandle, cfg, modulePathAndName, module, PAM_AUTH_ERR);
    }

    moduleAuthFunc = (int (*)(pam_handle_t*, int, int, const char**)) dlsym(module, "pam_sm_authenticate");

    if (!moduleAuthFunc)
    {
        DEBUG("Unable to find pam_sm_authenticate in module %s due to %s", cfg->subModule, dlerror());
        return finalize(pamHandle, cfg, modulePathAndName, module, PAM_AUTH_ERR);
    }

    retval = moduleAuthFunc(pamHandle, flags, cfg->subArgc, cfg->subArgv);

    DEBUG("Module %s returned %d", cfg->subModule, retval);
    DEBUG("PAM_SUCCESS = %d, PAM_MAXTRIES = %d", PAM_SUCCESS, PAM_MAXTRIES);

    if (retval == PAM_SUCCESS || retval == PAM_MAXTRIES)
    {
        cacheResult(cfg, cfg->callingUser, cfg->subModule, retval);
    }

    return finalize(pamHandle, cfg, modulePathAndName, module, retval);
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t* pamHandle UNUSED, int flags UNUSED, int argc UNUSED, const char** argv UNUSED)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t* pamHandle UNUSED, int flags UNUSED, int argc UNUSED, const char** argv UNUSED)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_open_session(pam_handle_t* pamHandle UNUSED, int flags UNUSED, int argc UNUSED, const char** argv UNUSED)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t* pamHandle UNUSED, int flags UNUSED, int argc UNUSED, const char** argv UNUSED)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t* pamHandle UNUSED, int flags UNUSED, int argc UNUSED, const char** argv UNUSED)
{
    return (PAM_SERVICE_ERR);
}
