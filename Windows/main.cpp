
#include <stdio.h>
#include <fstream>
#include "Core/elf_header.h"

int main(int argv, char **args)
{
    std::ifstream file;
    file.open("c:\\testelf", std::ios_base::binary);
    if (!file.is_open())
    {
        printf("elf file open fail\n");
        return 0;
    }
    file.seekg(0, std::ios::end);
    int file_size = file.tellg();
    file.seekg(0);
    char *file_content_buf = new char[file_size];
    file.read(file_content_buf, file_size);
    std::string file_content = std::string(file_content_buf, file_size);
    file.close();
    delete[]file_content_buf;

    elf_header header;
    header.from_string(file_content);
    printf(header.print().c_str());

    printf("hello, xAnSo");
    return 0;
}