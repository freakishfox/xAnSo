/******************************************************************************* 
 *  @file      util.cpp 2017\5\11 17:01:27 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#include "util.h"
#include <fstream>

/******************************************************************************/


/******************************************************************************/

std::string util::itoa(int i, int rdx)
{
    char _rs[100] = {0};
    ::_itoa_s(i, _rs, rdx);

    return std::string(_rs);
}

std::string util::read_file(std::string file)
{
    std::string file_content;

    char *file_content_buf = nullptr;
    try{
        std::ifstream file_;
        file_.open(file, std::ios_base::binary);
        if (!file_.is_open())
        {
            return file_content;
        }
        file_.seekg(0, std::ios::end);
        std::streamoff file_size = file_.tellg();
        file_.seekg(0);
        file_content_buf = new char[(unsigned int)file_size];
        file_.read(file_content_buf, file_size);
        file_content = std::string(file_content_buf, (unsigned int)file_size);
        file_.close();
        delete[]file_content_buf;
        file_content_buf = nullptr;
    }
    catch (...){
        if (!file_content_buf){
            delete[]file_content_buf;
        }
    }
    return file_content;
}
