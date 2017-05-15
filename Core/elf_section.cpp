/******************************************************************************* 
 *  @file      elf_section.cpp 2017\5\11 17:35:33 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#include "elf_section.h"
#include "log.h"
#include "util/util.h"

/******************************************************************************/

// -----------------------------------------------------------------------------
//  elf_section: Public, Constructor

elf_section::elf_section()
{
    memset(&header_, 0, sizeof(header_));
}

// -----------------------------------------------------------------------------
//  elf_section: Public, Destructor

elf_section::~elf_section()
{

}

bool elf_section::from_string(std::string str_content)
{
    LOG(DBG, "read elf section header from string");
    
    //check input string len is valid
    if (str_content.size() < sizeof(Elf32_Shdr)){
        LOG(ERR, "read section header from string, but string len invalid, len = %d", str_content.size());
        return false;
    }

    //copy content
    memcpy((char *)&header_, str_content.c_str(), sizeof(Elf32_Shdr));
    return true;
}

std::string elf_section::print()
{
    std::string styled_header;
    styled_header += ("Name: " + util::itoa(header_.sh_name) + "\n");
    styled_header += ("Type: " + util::itoa(header_.sh_type) + "\n");
    styled_header += ("Flags: " + util::itoa(header_.sh_flags) + "\n");
    styled_header += ("VA: " + util::itoa(header_.sh_addr) + "\n");
    styled_header += ("File Offset: " + util::itoa(header_.sh_offset) + "\n");
    styled_header += ("Size: " + util::itoa(header_.sh_size) + "\n");
    styled_header += ("Link: " + util::itoa(header_.sh_link) + "\n");
    styled_header += ("Info: " + util::itoa(header_.sh_info) + "\n");
    styled_header += ("Align: " + util::itoa(header_.sh_addralign) + "\n");
    styled_header += ("Entry Size: " + util::itoa(header_.sh_entsize) + "\n");

    return styled_header;
}

std::string elf_section::to_string()
{
    return std::string((const char*)&header_, sizeof(Elf32_Shdr));
}

/******************************************************************************/