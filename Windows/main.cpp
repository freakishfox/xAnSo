
#include <stdio.h>
#include <fstream>
#include "Core/elf_header.h"
#include "fix/section_fix.h"

#define MAX_PATH 260

void print_help(){
    printf("[+]here are all commands:\n");
    printf("\t[-]h --type help commands\n");
    printf("\t[-]build-section --build the so file section with information from the .dynamic segment\n");
    printf("\t[-]quit --quit xAnSo\n");
}

void print_hello(){
    printf("[+]what do you want next? type h for help, i am now on your command:\n");
}

bool process_cmd(char *cmd){
    if (!strcmp(cmd, "quit")){
        return false;
    }
    else if (!strcmp(cmd, "h")){
        print_help();
    }
    else if (!strcmp(cmd, "build-section")){
        printf("\t[-]input your file name:\n");
        char file_name[MAX_PATH] = { 0 };
        scanf_s("%s", file_name, MAX_PATH);

        //fix section
        section_fix fixer_;
        if (!fixer_.fix(file_name)){
            printf("\t[-]elf file section build fail\n");
        }
        else{
            std::string fixed_name_ = file_name + std::string(".fixed");
            if (!fixer_.save_as(fixed_name_)){
                printf("\t[-]save fixed elf file fail\n");
            }
            printf("\t[-]fixed file => %s\n", fixed_name_.c_str());
            printf("\t[-]elf file section build success!\n");
        }
    }

    return true;
}

int main(int argv, char **args)
{

    printf("------------------welcome to xAnSo------------------\n");
    printf("------------------tools for android-----------------\n");
  
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