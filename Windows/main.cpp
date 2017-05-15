
#include <stdio.h>
#include <fstream>
#include "Core/elf_header.h"
#include "fix/section_fix.h"

int main(int argv, char **args)
{
    section_fix fixer_;
    if (!fixer_.fix("c:\\testelf")){
        printf("fix elf file section fail\n");
        getchar();

        return 0;
    }

    if (!fixer_.save_as("c:\\testelf.fixed")){
        printf("save fixed elf file fail\n");
        getchar();

        return 0;
    }

    printf("fix elf file ok\n");
    getchar();

    return 0;
}