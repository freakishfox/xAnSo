
#include <stdio.h>
#include <fstream>
#include "Core/elf_header.h"
#include "fix/section_fix.h"
#include "log.h"

#define MAX_PATH 260

void print_help(){
    printf("[+]here are all commands:\n");
    printf("\t[-]h --type help commands\n");
    printf("\t[-]build-section --build the so file sections\n");
    printf("\t[-]quit --quit xAnSo\n");
}

void print_hello(){
    delay_print(COLOR_WHITE, "[+]what do you want next? \n");
    delay_print(COLOR_WHITE, "[+]type h for help, i am now on your command:");
}

bool process_cmd(char *cmd){
    if (!strcmp(cmd, "quit")){
        return false;
    }
    else if (!strcmp(cmd, "h")){
        print_help();
    }
    else if (!strcmp(cmd, "build-section")){
        delay_print(COLOR_WHITE, "\t[-]input your file name:");

        char file_name[MAX_PATH] = { 0 };
        scanf_s("%s", file_name, MAX_PATH);

        //fix section
        section_fix fixer_;
        if (!fixer_.fix(file_name)){
            delay_print(COLOR_RED, "\t[-]elf file section build fail!\n");
        }
        else{
            std::string fixed_name_ = file_name + std::string(".fixed");
            if (!fixer_.save_as(fixed_name_)){
                delay_print(COLOR_RED, "\t[-]save fixed elf file fail\n");
            }
            delay_print(COLOR_GREEN, "\t[-]fixed file => %s\n", fixed_name_.c_str());
            delay_print(COLOR_GREEN, "\t[-]elf file section build success!\n");
        }
    }

    return true;
}

int main(int argv, char **args)
{

    delay_print(COLOR_GREEN, "[+]welcome to xAnSo...\n");
    delay_print(COLOR_GREEN, "[+]tools for android...\n");

    while (true)
    {
        print_hello();

        char cmd_line[MAX_PATH] = { 0 };
        scanf_s("%s", cmd_line, MAX_PATH);
        if (!process_cmd(cmd_line)){
            break;
        }
    }

    printf("[+]xAnSo exit...");
    return 0;
}