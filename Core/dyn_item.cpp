/******************************************************************************* 
 *  @file      dyn_item.cpp 2017\5\11 20:37:00 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#include "dyn_item.h"
#include "log.h"
#include "util/util.h"

/******************************************************************************/

// -----------------------------------------------------------------------------
//  dyn_item: Public, Constructor

dyn_item::dyn_item()
{
    dyn_item_.d_tag = 0x12345678;
    dyn_item_.d_un.d_ptr = 0;
    dyn_item_.d_un.d_val = 0;
}

// -----------------------------------------------------------------------------
//  dyn_item: Public, Destructor

dyn_item::~dyn_item()
{

}

bool dyn_item::from_string(std::string str_content)
{
    LOG(DBG, "read dynamic item from string");

    if (str_content.size() < sizeof(Elf32_Dyn)){
        LOG(ERR, "read dynamic item from string, input string len invalid, len=%d", str_content.size());
        return false;
    }

    //copy content
    memcpy((char *)&dyn_item_, str_content.c_str(), sizeof(Elf32_Dyn));
    return true;
}

std::string dyn_item::print()
{
    std::string styled_section;
    styled_section += ("Tag: " + tag_2_string(dyn_item_.d_tag));
    styled_section += ("Value: " + util::itoa(dyn_item_.d_un.d_val));

    return styled_section;
}

std::string dyn_item::tag_2_string(int tag)
{
    switch (tag)
    {
    case DT_NULL:
        return "DT_NULL";
    case DT_NEEDED:
        return "DT_NEEDED";
    case DT_PLTRELSZ:
        return "DT_PLTRELSZ";
    case DT_PLTGOT:
        return "DT_PLTGOT";
    case DT_HASH:
        return "DT_HASH";
    case DT_STRTAB:
        return "DT_STRTAB";
    case DT_SYMTAB:
        return "DT_SYMTAB";
    case DT_RELA:
        return "DT_RELA";
    case DT_RELASZ:
        return "DT_RELASZ";
    case DT_RELAENT:
        return "DT_RELAENT";
    case DT_STRSZ:
        return "DT_STRSZ";
    case DT_SYMENT:
        return "DT_SYMENT";
    case DT_INIT:
        return "DT_INIT";
    case DT_FINI:
        return "DT_FINI";
    case DT_SONAME:
        return "DT_SONAME";
    case DT_RPATH:
        return "DT_RPATH";
    case DT_SYMBOLIC:
        return "DT_SYMBOLIC";
    case DT_REL:
        return "DT_REL";
    case DT_RELSZ:
        return "DT_RELSZ";
    case DT_RELENT:
        return "DT_RELENT";
    case DT_PLTREL:
        return "DT_PLTREL";
    case DT_DEBUG:
        return "DT_DEBUG";
    case DT_TEXTREL:
        return "DT_TEXTREL";
    case DT_JMPREL:
        return "DT_JMPREL";
    case DT_BIND_NOW:
        return "DT_BIND_NOW";
    case DT_INIT_ARRAY:
        return "DT_INIT_ARRAY";
    case DT_FINI_ARRAY:
        return "DT_FINI_ARRAY";
    case DT_INIT_ARRAYSZ:
        return "DT_INIT_ARRAYSZ";
    case DT_FINI_ARRAYSZ:
        return "DT_FINI_ARRAYSZ";
    case DT_RUNPATH:
        return "DT_RUNPATH";
    case DT_FLAGS:
        return "DT_FLAGS";
    //case DT_ENCODING:
    case DT_PREINIT_ARRAY:
        return "DT_PREINIT_ARRAY";
    case DT_PREINIT_ARRAYSZ:
        return "DT_PREINIT_ARRAYSZ";
    case	DT_NUM:
        return "DT_NUM";
    case DT_LOOS:
        return "DT_LOOS";
    case DT_HIOS:
        return "DT_HIOS";
    case DT_LOPROC:
        return "DT_LOPROC";
    case DT_HIPROC:
        return "DT_HIPROC";
    case DT_PROCNUM:
        return "DT_PROCNUM";
    default:
        break;
    }

    return "DT_UNKNOWN";
}

std::string dyn_item::to_string()
{
    return std::string((char *)&dyn_item_, sizeof(Elf32_Dyn));
}

/******************************************************************************/