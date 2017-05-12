/******************************************************************************* 
 *  @file      section_fix.cpp 2017\5\12 19:46:41 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#include "section_fix.h"
#include "log.h"
#include "util/util.h"


/******************************************************************************/

// -----------------------------------------------------------------------------
//  section_fix: Public, Constructor

section_fix::section_fix()
{

}

// -----------------------------------------------------------------------------
//  section_fix: Public, Destructor

section_fix::~section_fix()
{

}

bool section_fix::fix(std::string src_file)
{
    std::string file_content = util::read_file(src_file);
    if (file_content.empty()){
        LOG(ERR, "try fix elf section, but file content empty");
        return false;
    }

    //save file content
    file_content_ = file_content;

    //pre load
    if (!pre_load()){
        LOG(ERR, "try fix elf section, but pre load elf file fail");
        return false;
    }



    return false;
}

bool section_fix::save_as(std::string dst_file)
{
    return false;
}

bool section_fix::pre_load()
{
    elf_header elf_header_;
    if (!elf_header_.from_string(file_content_)){
        LOG(ERR, "try fix elf section, but elf header invalid");
        return false;
    }

    Elf32_Ehdr header_ = elf_header_.get_header();
    Elf32_Off program_header_table = header_.e_phoff;
    Elf32_Half program_header_count = header_.e_phnum;
    for (int idx = 0; idx < program_header_count; idx++){

        std::string segment_content = file_content_.c_str() + program_header_table + idx * sizeof(Elf32_Phdr);
        elf_segment segment_;
        segment_.from_string(segment_content);
        if (PT_LOAD == segment_.get_header().p_type){
            //found pt_load segment
            vec_load_.push_back(segment_);
        }
        else if (PT_DYNAMIC == segment_.get_header().p_type){
            //found pt_dynamic segment
            dynamic_section_.from_string(segment_content);
        }
    }

    return (vec_load_.size() > 0);
}

/******************************************************************************/