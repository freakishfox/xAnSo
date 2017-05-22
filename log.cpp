/******************************************************************************* 
 *  @file      log.cpp 2017\5\11 15:24:27 $
 *  @author    df
 *  @brief     
 ******************************************************************************/


#include "log.h"

void LOG(const char *level, const char *log_format, ...){
    
    char    szOut[4096] = { 0 };
    va_list var_arg;
    va_start(var_arg, log_format);
    vsprintf(szOut, log_format, var_arg);

    if (!stricmp(level, ERR)){
        delay_print(COLOR_RED, "\t[-]");
        delay_print(COLOR_RED, ERR);
        delay_print(COLOR_RED, szOut);
        delay_print(COLOR_RED, "\n");
    }
    else if(!stricmp(level, WARN)){
        delay_print(COLOR_YELLOW, "\t[-]");
        delay_print(COLOR_YELLOW, WARN);
        delay_print(COLOR_YELLOW, szOut);
        delay_print(COLOR_YELLOW, "\n");
    }
    else{
        delay_print(COLOR_WHITE, "\t[-]");
        delay_print(COLOR_WHITE, level);
        delay_print(COLOR_WHITE, szOut);
        delay_print(COLOR_WHITE, "\n");
    }

    va_end(var_arg);
}



void COLOR_PRINT(const int color, const char *text){
#ifdef WINDOWS_BUILD
    //windows实现
    // 
    DWORD                       dwWs;
    HANDLE                      hConsoleOutput;
    CONSOLE_SCREEN_BUFFER_INFO  screenBufferInfo;
    WORD                        wAttributes;

    hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(hConsoleOutput, &screenBufferInfo);

    switch (color)
    {
    case COLOR_RED:       // 一般信息  
        wAttributes = FOREGROUND_RED | FOREGROUND_INTENSITY;
        break;
    case COLOR_GREEN:  
        wAttributes = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        break;
    case COLOR_BLUE:        // 错误信息，红色  
        wAttributes = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        break;
    case COLOR_YELLOW:
        wAttributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        break;
    default:
        wAttributes = screenBufferInfo.wAttributes;
    }

    SetConsoleTextAttribute(hConsoleOutput, wAttributes);
    WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), text, strlen(text), &dwWs, NULL);
    SetConsoleTextAttribute(hConsoleOutput, screenBufferInfo.wAttributes);
#else
    printf(text);
#endif
}

void delay_print(const int color, const char*print_format, ...){
    va_list                     argPtr;
    char                        szOut[4096] = { 0 };

    va_start(argPtr, print_format);
    vsprintf(szOut, print_format, argPtr);

    for (int idx = 0; idx < 4096; idx++){
        if (!szOut[idx]){
            break;
        }

        char step_text[2] = { 0 };
        step_text[0] = szOut[idx];
        COLOR_PRINT(color, step_text);

        Sleep(delay_print_interval);
    }
    va_end(argPtr);
}

/******************************************************************************/