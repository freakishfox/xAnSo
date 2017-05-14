/******************************************************************************* 
 *  @file      elf_segment.cpp 2017\5\11 19:06:03 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#include "elf_segment.h"
#include "log.h"
#include "util/util.h"

/******************************************************************************/

// -----------------------------------------------------------------------------
//  elf_segment: Public, Constructor

elf_segment::elf_segment()
{
    memset(&header_, 0, sizeof(header_));
}

// -----------------------------------------------------------------------------
//  elf_segment: Public, Destructor

elf_segment::~elf_segment()
{

}

bool elf_segment::from_string(std::string str_content)
{
    LOG(DBG, "read elf program header from string");
    
    //check if string contains enough content
    if (str_content.size() < sizeof(Elf32_Phdr)){
        LOG(ERR, "read elf program header, but input string len is invalid, len=%d", str_content.size());
        return false;
    }

    //copy content
    memcpy((char *)&header_, str_content.c_str(), sizeof(Elf32_Phdr));
    return true;
}

std::string elf_segment::print()
{
    std::string styled_header;
    styled_header += ("Type: " + util::itoa(header_.p_type) + "\n");
    styled_header += ("Flags: " + util::itoa(header_.p_flags) + "\n");
    styled_header += ("Offset: " + util::itoa(header_.p_offset) + "\n");
    styled_header += ("VA: " + util::itoa(header_.p_vaddr) + "\n");
    styled_header += ("PA: " + util::itoa(header_.p_paddr) + "\n");
    styled_header += ("File Size: " + util::itoa(header_.p_filesz) + "\n");
    styled_header += ("Mem Size: " + util::itoa(header_.p_memsz) + "\n");
    styled_header += ("Align: " + util::itoa(header_.p_align) + "\n");

    return styled_header;
}

/******************************************************************************/