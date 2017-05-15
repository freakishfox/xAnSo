/******************************************************************************* 
 *  @file      elf_header.cpp 2017\5\11 9:18:00 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#include "elf_header.h"
#include "log.h"
#include "util/util.h"
#include <string>

/******************************************************************************/

// -----------------------------------------------------------------------------
//  elf_header: Public, Constructor

elf_header::elf_header()
{
    memset(&header_, 0, sizeof(header_));
}

// -----------------------------------------------------------------------------
//  elf_header: Public, Destructor

elf_header::~elf_header()
{

}

bool elf_header::from_string(std::string str_content)
{
    //check content size
    if (str_content.size() < sizeof(Elf32_Ehdr)){
        LOG(ERR, "parse elf_header from string, but input string length invalid, len=%d", str_content.size());
        return false;
    }

    //copy header content
    memcpy((char *)&header_, str_content.c_str(), sizeof(Elf32_Ehdr));

    //check if header content is valid
    return is_valid();
}

static int GetTargetElfMachine() {
#if defined(__arm__)
    return EM_ARM;
#elif defined(__aarch64__)
    return EM_AARCH64;
#elif defined(__i386__)
    return EM_386;
#elif defined(__mips__)
    return EM_MIPS;
#elif defined(__x86_64__)
    return EM_X86_64;
#endif

    return EM_ARM;
}

bool elf_header::is_valid()
{
    LOG(DBG, "elf header now check is valid...");
    if (memcmp(header_.e_ident, ELFMAG, SELFMAG) != 0) {
        LOG(ERR, "elf header magic is invalid");
        return false;
    }

    // Try to give a clear diagnostic for ELF class mismatches, since they're
    // an easy mistake to make during the 32-bit/64-bit transition period.
    int elf_class = header_.e_ident[EI_CLASS];
    if (elf_class != ELFCLASS32) {
        if (elf_class == ELFCLASS64) {
            LOG(WARN, "elf header is 64-bit instead of 32-bit");
        }
        else {
            LOG(WARN, "elf header has unknown ELF class: %d", elf_class);
        }
        return false;
    }

    if (header_.e_ident[EI_DATA] != ELFDATA2LSB) {
        LOG(ERR, "elf header is not little-endian: %d", header_.e_ident[EI_DATA]);
        return false;
    }

    if (header_.e_type != ET_DYN) {
        LOG(ERR, "elf header has unexpected e_type: %d", header_.e_type);
        return false;
    }

    if (header_.e_version != EV_CURRENT) {
        LOG(ERR, "elf header has unexpected e_version: %d", header_.e_version);
        return false;
    }

    if (header_.e_machine != GetTargetElfMachine()) {
        LOG(ERR, "elf header has unexpected e_machine: %d", header_.e_machine);
        return false;
    }

    LOG(DBG, "ok, elf header is valid");
    return true;
}

std::string elf_header::print()
{
    std::string styled_header;
    styled_header += ("Elf Header Size: " + util::itoa(header_.e_ehsize) + "\n");
    styled_header += ("Type: " + type_2_string(header_.e_type) + "\n");
    styled_header += ("Machine: " + util::itoa(header_.e_machine) + "\n");
    styled_header += ("Version: " + util::itoa(header_.e_version) + "\n");
    styled_header += ("Entry: " + util::itoa(header_.e_entry) + "\n");
    styled_header += ("Program Header Offset: " + util::itoa(header_.e_phoff) + "\n");
    styled_header += ("Program Header Item Size: " + util::itoa(header_.e_phentsize) + "\n");
    styled_header += ("Program Header Count: " + util::itoa(header_.e_phnum) + "\n");
    styled_header += ("Section Header Offset: " + util::itoa(header_.e_shoff) + "\n");
    styled_header += ("Section Header Item Size: " + util::itoa(header_.e_shentsize) + "\n");
    styled_header += ("Section Header Count: " + util::itoa(header_.e_shnum) + "\n");
    styled_header += ("Section Header StringTable Index: " + util::itoa(header_.e_shstrndx) + "\n");
    styled_header += ("Flags: " + util::itoa(header_.e_flags) + "\n");
    
    return styled_header;
}

std::string elf_header::type_2_string(Elf32_Half type)
{
    switch (type){
    case ET_NONE:
        return "ET_NONE";
    case ET_REL:
        return "ET_REL";
    case ET_EXEC:
        return "ET_EXEC";
    case ET_DYN:
        return "ET_DYN";
    case ET_CORE:
        return "ET_CORE";
    case ET_LOPROC:
        return "ET_LOPROC";
    case ET_HIPROC:
        return "ET_HIPROC";
    default:
        return "ET_UNKOWN";
    }
}

std::string elf_header::to_string()
{
    std::string elf_header_string_;
    return std::string((const char*)&header_, sizeof(Elf32_Ehdr));
}

/******************************************************************************/