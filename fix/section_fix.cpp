/******************************************************************************* 
 *  @file      section_fix.cpp 2017\5\12 19:46:41 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#include "section_fix.h"
#include "log.h"
#include "util/util.h"
#include <algorithm>


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

    //pre load .dynamic .load segments
    if (!pre_load()){
        LOG(ERR, "try fix elf section, but pre load elf file fail");
        return false;
    }

    //first create
    if (!first_create_sections()){
        LOG(ERR, "try fix elf sectoins, but first create sections fail");
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
    //we load segments whose informations are necessary for the comming operations
    // we load PT_LOAD and PT_DYNAMIC segments, which shall exist in an valid elf
    
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

bool section_fix::first_create_sections()
{
    //first we create sections with informations from the .dynamic segment
    // if information in a section in not full, we fix it later
    
//#define FILL_SECTION(dyn_tab, dyn_sz, type, flag, name)\

    //create .synstr
    dyn_item dyn_str_tab = dynamic_section_.find_dyn_by_tag(DT_STRTAB);
    dyn_item dyn_str_sz = dynamic_section_.find_dyn_by_tag(DT_STRSZ);
    if (dyn_str_tab.is_valid() 
        && dyn_str_sz.is_valid()){
        elf_section str_section_;
        Elf32_Shdr header_ = str_section_.get_header();
        header_.sh_type = SHT_STRTAB;
        header_.sh_addr = dyn_str_tab.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = dyn_str_sz.get_value();
        header_.sh_flags = SHF_ALLOC;
        header_.sh_name = find_string_idx_in_strtab(".synstr");

        vec_created_section_.push_back(str_section_);
        LOG(DBG, ".synstr section created");
    }

    //create  .dynsym
    dyn_item dyn_sym = dynamic_section_.find_dyn_by_tag(DT_SYMTAB);
    if (dyn_sym.is_valid()){
        elf_section sym_section_;
        Elf32_Shdr header_ = sym_section_.get_header();
        header_.sh_type = SHT_SYMTAB;
        header_.sh_addr = dyn_sym.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = 0; //???? fix me
        header_.sh_flags = SHF_ALLOC;
        header_.sh_name = find_string_idx_in_strtab(".dynsym");

        vec_created_section_.push_back(sym_section_);
        LOG(DBG, ".dynsym section created");
    }

    //create .rel.plt
    dyn_item dyn_rel_plt = dynamic_section_.find_dyn_by_tag(DT_JMPREL);
    dyn_item dyn_rel_plt_sz = dynamic_section_.find_dyn_by_tag(DT_PLTRELSZ);
    if (dyn_rel_plt.is_valid()
        && dyn_rel_plt_sz.is_valid()){
        elf_section rel_plt_section_;
        Elf32_Shdr header_ = rel_plt_section_.get_header();
        header_.sh_type = SHT_REL;
        header_.sh_addr = dyn_rel_plt.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = dyn_rel_plt_sz.get_value();
        header_.sh_flags = SHF_ALLOC;
        header_.sh_name = find_string_idx_in_strtab(".rel.plt");

        vec_created_section_.push_back(rel_plt_section_);
        LOG(DBG, ".rel.plt section created");
    }

    //create .rel.dyn
    dyn_item dyn_rel_dyn = dynamic_section_.find_dyn_by_tag(DT_REL);
    dyn_item dyn_rel_dyn_sz = dynamic_section_.find_dyn_by_tag(DT_RELSZ);
    if (dyn_rel_dyn.is_valid()
        && dyn_rel_dyn_sz.is_valid()){
        elf_section rel_dyn_section_;
        Elf32_Shdr header_ = rel_dyn_section_.get_header();
        header_.sh_type = SHT_REL;
        header_.sh_addr = dyn_rel_dyn.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = dyn_rel_dyn_sz.get_value();
        header_.sh_flags = SHF_ALLOC;
        header_.sh_name = find_string_idx_in_strtab(".rel.dyn");

        vec_created_section_.push_back(rel_dyn_section_);
        LOG(DBG, ".rel.dyn section created");
    }

    //create .init_array
    dyn_item dyn_init_array = dynamic_section_.find_dyn_by_tag(DT_INIT_ARRAY);
    dyn_item dyn_init_array_sz = dynamic_section_.find_dyn_by_tag(DT_INIT_ARRAYSZ);
    if (dyn_init_array.is_valid()
        && dyn_init_array_sz.is_valid()){
        elf_section init_array_section_;
        Elf32_Shdr header_ = init_array_section_.get_header();
        header_.sh_type = SHT_INIT_ARRAY;
        header_.sh_addr = dyn_init_array.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = dyn_init_array_sz.get_value();
        header_.sh_flags = SHF_ALLOC | SHF_WRITE;
        header_.sh_name = find_string_idx_in_strtab(".init_array");

        vec_created_section_.push_back(init_array_section_);
        LOG(DBG, ".init_array section created");
    }

    //create .fini_array
    dyn_item dyn_fini_array = dynamic_section_.find_dyn_by_tag(DT_FINI_ARRAY);
    dyn_item dyn_fini_array_sz = dynamic_section_.find_dyn_by_tag(DT_FINI_ARRAYSZ);
    if (dyn_fini_array.is_valid()
        && dyn_fini_array_sz.is_valid()){
        elf_section fini_array_section_;
        Elf32_Shdr header_ = fini_array_section_.get_header();
        header_.sh_type = SHT_FINI_ARRAY;
        header_.sh_addr = dyn_fini_array.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = dyn_fini_array_sz.get_value();
        header_.sh_flags = SHF_ALLOC | SHF_WRITE;
        header_.sh_name = find_string_idx_in_strtab(".fini_array");

        vec_created_section_.push_back(fini_array_section_);
        LOG(DBG, ".fini_array section created");
    }

    return true;
}

int section_fix::calc_VA_FA_gap(Elf32_Addr section_addr)
{
    //0. find which load segment is the section belongs
    //1. calc the address gap bettwen virtual address and file offset
    //2. any section in this load segment shall have the same address gap as the coreponding load segment
    
    //0. sort the loaded segments
    if (!vec_load_.size()){
        LOG(ERR, "try calc virtual addr file offset gap, but PT_LOAD vector empty");
        return 0;
    }
    
    std::sort(vec_load_.begin(), vec_load_.end(), 
        [=](elf_segment &item1, elf_segment &item2)->bool{
        return item1.get_header().p_paddr < item2.get_header().p_paddr;
    });

    //1. now find it
    for (auto itr : vec_load_){
        if (itr.get_header().p_paddr >= section_addr){
            //got it
            return (itr.get_header().p_paddr - itr.get_header().p_offset);
        }
    }

    LOG(ERR, "try calc virtual addr file offset gap, but section not in any PT_LOAD segment");
    return 0;
}

int section_fix::find_string_idx_in_strtab(std::string str)
{
    if (sh_str_.empty()){
        //prepare the section header string
        
        sh_str_.append('\0'); //idx = 0
        sh_str_.append(".interp\0"); //idx = 1
        sh_str_.append(".note.gnu.build-i\0");
        sh_str_.append(".dynsym\0");
        sh_str_.append(".dynstr\0");
        sh_str_.append(".hash\0");
        sh_str_.append(".gnu.version\0");
        sh_str_.append(".gnu.version_d\0");
        sh_str_.append(".gnu.version_r\0");
        sh_str_.append(".rel.dyn\0");
        sh_str_.append(".rel.plt\0");
        sh_str_.append(".text\0");
        sh_str_.append(".ARM.extab\0");
        sh_str_.append(".ARM.exidx\0");
        sh_str_.append(".rodata\0");
        sh_str_.append(".fini_array\0");
        sh_str_.append(".init_array\0");
        sh_str_.append(".dynamic\0");
        sh_str_.append(".got\0");
        sh_str_.append(".data\0");
        sh_str_.append(".bss\0");
        sh_str_.append(".comment\0");
        sh_str_.append(".note.gnu.gold-ve\0");
        sh_str_.append(".ARM.attributes\0");
        sh_str_.append(".shstrtab\0");
    }

    std::string::size_type idx = sh_str_.find_first_of(str);
    if (std::string::npos != idx){
        return (int)idx;
    }

    LOG(ERR, "try to find string index in section header string table, but can't find it");
    return -1;
}

/******************************************************************************/