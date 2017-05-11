/******************************************************************************* 
 *  @file      log.cpp 2017\5\11 15:24:27 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#include "log.h"
void LOG(const char *level, const char *log_format, ...){
    printf("[%s]", level);
    va_list var_arg;
    va_start(var_arg, log_format);

    //todo print content
    printf(log_format, *var_arg);
    printf("\n");

    va_end(var_arg);
}

/******************************************************************************/