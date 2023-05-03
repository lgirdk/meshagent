#ifndef _XMESH_DIAG_
#define _XMESH_DIAG_

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>

char* getFormattedTime(void);
FILE* g_flog = NULL;        //for logging to file
bool  g_clog = false;       //for logging to console

#define LOG_FILE_BBOX     "/rdklogs/logs/MeshBlackbox.log"
#define LOG_FILE_BBOXDMP  "/rdklogs/logs/MeshBlackboxDumps.log"
#define __LOG__(format, loglevel, file, color_start, color_end, ...)                                                      \
    do {                                                                                                            \
        if (g_clog) {                                                                                               \
            printf("%s%s %-5s " format "%s", color_start, getFormattedTime(), loglevel, ## __VA_ARGS__, color_end); \
        }                                                                                                           \
        g_flog = fopen(file, "a");                                                                         \
        if (g_flog) {                                                                                               \
            fprintf(g_flog, "%s %-5s " format, getFormattedTime(), loglevel, ## __VA_ARGS__);                       \
            fclose(g_flog);                                                                                         \
            g_flog = NULL;                                                                                          \
        }                                                                                                           \
    } while (0)

#define LOGINFO(format, ...)      __LOG__(format, "INFO" , LOG_FILE_BBOX, "", "", ## __VA_ARGS__)
#define LOGSUCCESS(format, ...)   __LOG__(format, "INFO" , LOG_FILE_BBOX, "\033[32m", "\033[m", ## __VA_ARGS__)
#define LOGERROR(format, ...)     __LOG__(format, "ERROR", LOG_FILE_BBOX, "\033[31m", "\033[m", ## __VA_ARGS__)

#define LOGDUMPINFO(format, ...)  __LOG__(format, "INFO" , LOG_FILE_BBOXDMP, "", "", ## __VA_ARGS__)
#define LOGDUMPERROR(format, ...) __LOG__(format, "ERROR", LOG_FILE_BBOXDMP, "\033[31m", "\033[m", ## __VA_ARGS__)

#define LOG_TO_CONSOLE() g_clog = true

void xmesh_diag_start(int interval, bool dumps_enabled, bool wfo, int delay);
void xmesh_diag_stop();

#endif //_XMESH_DIAG_
