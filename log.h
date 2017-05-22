/*******************************************************************************
 *  @file      log.h 2017\5\11 14:17:38 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#ifndef LOG_8EC8D1A7_8377_42DC_9AB1_7775907F16EB_H__
#define LOG_8EC8D1A7_8377_42DC_9AB1_7775907F16EB_H__

#include "config.h"

#ifdef WINDOWS_BUILD
#include <Windows.h>
#endif

#include <stdarg.h>
#include <strsafe.h>


//common log
#define INFO "[INFO]"
#define ERR "[ERROR]"
#define DBG "[DEBUG]"
#define WARN "[WARNING]"

#define COLOR_RED 0xFF0000
#define COLOR_GREEN 0x00FF00
#define COLOR_BLUE 0x0000FF
#define COLOR_WHITE 0xFFFFFF
#define COLOR_YELLOW 0xFFFF00

void LOG(const char *level, const char *log_format, ...);
void delay_print(const int color, const char*print_format, ...);

#endif// LOG_8EC8D1A7_8377_42DC_9AB1_7775907F16EB_H__
