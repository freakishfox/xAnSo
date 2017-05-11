/******************************************************************************* 
 *  @file      dyn_section.cpp 2017\5\11 23:34:00 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#include "dyn_section.h"
#include "log.h"

/******************************************************************************/

// -----------------------------------------------------------------------------
//  dyn_section: Public, Constructor

dyn_section::dyn_section()
{

}

// -----------------------------------------------------------------------------
//  dyn_section: Public, Destructor

dyn_section::~dyn_section()
{

}

/******************************************************************************/
bool dyn_section::from_string(std::string str_content)
{
    LOG(DBG, "read dyn section from string");
    if (str_content.empty()){
        LOG(ERR, "read dyn items from string, but string empty");
        return false;
    }

    for (Elf32_Dyn *dyn = (Elf32_Dyn *)str_content.c_str(); dyn->d_tag != DT_NULL; dyn++){
        LOG(DBG, "read dyn item flag=%d, value=0x%x", dyn->d_tag, dyn->d_un.d_val);

        dyn_item item;
        item.from_string((char *)dyn);
        items_.push_back(item);
    }
    return true;
}

std::string dyn_section::to_string()
{
    std::string dyn_section_;
    for (dyn_item itr : items_){
        dyn_section_.append(itr.to_string());
    }

    LOG(DBG, "dyn_section to string");
    return dyn_section_;
}

std::string dyn_section::print()
{
    std::string styled_section;
    for (dyn_item itr : items_){
        styled_section += (itr.print() + "\n");
    }

    LOG(DBG, "print dyn section content");
    return styled_section;
}

