/*******************************************************************************
 *  @file      log.h 2017\5\11 14:17:38 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#ifndef LOG_8EC8D1A7_8377_42DC_9AB1_7775907F16EB_H__
#define LOG_8EC8D1A7_8377_42DC_9AB1_7775907F16EB_H__

#include <stdarg.h>
#include <strsafe.h>

//common log
#define INFO "INFO"
#define ERR "ERROR"
#define DBG "DEBUG"
#define WARN "WARNING"

void LOG(const char *level, const char *log_format, ...);

#endif// LOG_8EC8D1A7_8377_42DC_9AB1_7775907F16EB_H__
