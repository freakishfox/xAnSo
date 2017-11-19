/******************************************************************************* 
 *  @file      section_fix.cpp 2017\5\12 19:46:41 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#include "section_fix.h"
#include "log.h"
#include "util/util.h"
#include <algorithm>
#include <fstream>


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

    //need fix

    return true;
}

bool section_fix::save_as(std::string dst_file)
{
    //0. Serialize created sections as a string
    //1. save created sections to the end of the file
    //2. adjust elf file header coresponding fields
    
    std::string section_table;
    //0. created the first null section
    elf_section null_section;
    section_table += null_section.to_string();

    //1. create sections from .dynamic segments
    for (auto itr : vec_created_section_)
    {
        section_table += itr.to_string();
    } 
    
    //
    std::sort(vec_load_.begin(), vec_load_.end(),
        [=](elf_segment &item1, elf_segment &item2)->bool{
        return item1.get_header().p_paddr < item2.get_header().p_paddr;
    });

    //2. create .shstrtab section
    Elf32_Off sh_str_tab = file_content_.size();
    Elf32_Word sh_str_tab_size = sh_str_.size();
    elf_section sh_str_section;
    Elf32_Shdr &header_ = sh_str_section.get_header();
    header_.sh_name = find_string_idx_in_strtab(".shstrtab");
    header_.sh_offset = sh_str_tab;
    header_.sh_size = sh_str_tab_size;
    elf_segment last_segment = vec_load_[vec_load_.size() - 1];
    header_.sh_addr = header_.sh_offset + (last_segment.get_header().p_paddr - last_segment.get_header().p_offset);
    header_.sh_type = SHT_STRTAB;
    header_.sh_flags = SHF_ALLOC;
    header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;

    section_table += sh_str_section.to_string();
    //3. append shstrtab section content to the end of the file
    
    file_content_ += sh_str_;
    Elf32_Off sh_str_offset = file_content_.size();

    file_content_ += section_table;

    //4. adjust elf header
    elf_header elf_file_header;
    if (!elf_file_header.from_string(file_content_)){
        LOG(ERR, "try to save elf file, but header invalid");
        return false;
    }

    Elf32_Ehdr &elf_file_header_ = elf_file_header.get_header();
    elf_file_header_.e_shentsize = sizeof(Elf32_Shdr);
    elf_file_header_.e_shnum = vec_created_section_.size() + 2;
    elf_file_header_.e_shoff = sh_str_offset;
    elf_file_header_.e_shstrndx = elf_file_header_.e_shnum - 1;
    
    //save file
    std::ofstream out_file_;
    out_file_.open(dst_file, std::ios_base::binary);
    if (!out_file_.is_open()){
        LOG(ERR, "try save elf file, but fail, error=%d", errno);
        return false;
    }

    std::string elf_header_content_ = elf_file_header.to_string();
    out_file_.write(elf_header_content_.c_str(), elf_header_content_.size());
    out_file_.write(file_content_.c_str() + elf_file_header.size(), file_content_.size() - elf_file_header.size());
    LOG(DBG, "save fixed elf file ok");
    return true;
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

    Elf32_Ehdr &header_ = elf_header_.get_header();
    Elf32_Off program_header_table = header_.e_phoff;
    Elf32_Half program_header_count = header_.e_phnum;
    for (int idx = 0; idx < program_header_count; idx++){

        std::string segment_content = std::string(file_content_.c_str() + program_header_table + idx * sizeof(Elf32_Phdr), sizeof(Elf32_Phdr));
        elf_segment segment_;
        segment_.from_string(segment_content);
        if (PT_LOAD == segment_.get_header().p_type){
            //found pt_load segment
            vec_load_.push_back(segment_);
        }
        else if (PT_DYNAMIC == segment_.get_header().p_type){
            //found pt_dynamic segment
            std::string dynamic_segment_content = std::string(file_content_.c_str() + segment_.get_header().p_offset, segment_.get_header().p_filesz);
            dynamic_section_.from_string(dynamic_segment_content);
            dynamic_section_.save_section_information(segment_content);
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
        Elf32_Shdr &header_ = str_section_.get_header();
        header_.sh_type = SHT_STRTAB;
        header_.sh_addr = dyn_str_tab.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = dyn_str_sz.get_value();
        header_.sh_flags = SHF_ALLOC;
        header_.sh_name = find_string_idx_in_strtab(".dynstr");
        header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;

        vec_created_section_.push_back(str_section_);
        LOG(DBG, ".dynstr section created");
    }

    //create  .dynsym
    dyn_item dyn_sym = dynamic_section_.find_dyn_by_tag(DT_SYMTAB);
    dyn_item dyn_sym_entry_size = dynamic_section_.find_dyn_by_tag(DT_SYMENT);
    //dyn_item dyn_sym_sz = dynamic_section_.find_dyn_by_tag(DT_SYMTAB);
    if (dyn_sym.is_valid()){
        elf_section sym_section_;
        Elf32_Shdr &header_ = sym_section_.get_header();
        header_.sh_type = SHT_SYMTAB;
        header_.sh_addr = dyn_sym.get_addr();
        header_.sh_entsize = dyn_sym_entry_size.get_value();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = 0; 
        header_.sh_flags = SHF_ALLOC;
        header_.sh_name = find_string_idx_in_strtab(".dynsym");
        header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;
        header_.sh_link = 1; //very important, link means symname found base section, and now 1==.dynstr section index, because i put it in the second pos in the created_section_vec

        vec_created_section_.push_back(sym_section_);
        LOG(DBG, ".dynsym section created");
    }

    //create .hash
    dyn_item dyn_hash = dynamic_section_.find_dyn_by_tag(DT_HASH);
    if (dyn_hash.is_valid()){
        elf_section hash_section_;
        Elf32_Shdr &header_ = hash_section_.get_header();
        header_.sh_type = SHT_HASH;
        header_.sh_name = find_string_idx_in_strtab(".hash");
        header_.sh_addr = dyn_hash.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);

        //calc hash size
        int *hash_content_ = (int *)(file_content_.c_str() + header_.sh_offset);
        header_.sh_size = (hash_content_[0] + hash_content_[1] + 2) * sizeof(int);

        header_.sh_flags = SHF_ALLOC;
        header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;

        vec_created_section_.push_back(hash_section_);
        LOG(DBG, ".hash section created");
    }

    //create .rel.dyn
    dyn_item dyn_rel_dyn = dynamic_section_.find_dyn_by_tag(DT_REL);
    dyn_item dyn_rel_dyn_sz = dynamic_section_.find_dyn_by_tag(DT_RELSZ);
    dyn_item dyn_rel_dyn_entry_size = dynamic_section_.find_dyn_by_tag(DT_RELENT);
    if (dyn_rel_dyn.is_valid()
        && dyn_rel_dyn_sz.is_valid()){
        elf_section rel_dyn_section_;
        Elf32_Shdr &header_ = rel_dyn_section_.get_header();
        header_.sh_type = SHT_REL;
        header_.sh_addr = dyn_rel_dyn.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = dyn_rel_dyn_sz.get_value();
        header_.sh_entsize = dyn_rel_dyn_entry_size.get_value();
        header_.sh_flags = SHF_ALLOC;
        header_.sh_name = find_string_idx_in_strtab(".rel.dyn");
        header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;
        header_.sh_link = 2;

        vec_created_section_.push_back(rel_dyn_section_);
        LOG(DBG, ".rel.dyn section created");
    }

    //create .rel.plt
    dyn_item dyn_rel_plt = dynamic_section_.find_dyn_by_tag(DT_JMPREL);
    dyn_item dyn_rel_plt_sz = dynamic_section_.find_dyn_by_tag(DT_PLTRELSZ);
    //dyn_item dyn_rel_plt_entry_size = dynamic_section_.find_dyn_by_tag(DT_P)  //?????fixme 
    if (dyn_rel_plt.is_valid()
        && dyn_rel_plt_sz.is_valid()){
        elf_section rel_plt_section_;
        Elf32_Shdr &header_ = rel_plt_section_.get_header();
        header_.sh_type = SHT_REL;
        header_.sh_addr = dyn_rel_plt.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = dyn_rel_plt_sz.get_value();
        header_.sh_entsize = 8; //fixme, get from .dynamic ??
        header_.sh_flags = SHF_ALLOC;
        header_.sh_name = find_string_idx_in_strtab(".rel.plt");
        header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;
        header_.sh_link = 2;

        vec_created_section_.push_back(rel_plt_section_);
        LOG(DBG, ".rel.plt section created");
    }

    //create .plt
    Elf32_Addr plt_section_addr_ = 0;
    Elf32_Word plt_section_size = 0;
    {
        //just treat the data behind .rel.plt as .plt section
        elf_section plt_section_;
        Elf32_Shdr &header_ = plt_section_.get_header();
        header_.sh_type = SHT_PROGBITS;
        header_.sh_addr = dyn_rel_plt.get_addr() + dyn_rel_plt_sz.get_value();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = (20 + 12 * (dyn_rel_plt_sz.get_value()) / sizeof(Elf32_Rel)); //please reference to the plt struct
        header_.sh_flags = SHF_EXECINSTR | SHF_ALLOC;
        header_.sh_name = find_string_idx_in_strtab(".plt");
        header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;

        vec_created_section_.push_back(plt_section_);
        LOG(DBG, ".plt section created");

        //save for .text
        plt_section_addr_ = header_.sh_addr;
        plt_section_size = header_.sh_size;
    }

    //create .text
    {
        //just treat the data behind .plt as .text section
        elf_section text_section_;
        Elf32_Shdr &header_ = text_section_.get_header();
        header_.sh_type = SHT_PROGBITS;
        header_.sh_name = find_string_idx_in_strtab(".text");
        header_.sh_flags = SHF_EXECINSTR | SHF_ALLOC;
        header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;
        header_.sh_addr = plt_section_addr_ + plt_section_size;
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = file_content_.size() - header_.sh_offset;

        vec_created_section_.push_back(text_section_);
        LOG(DBG, ".text section created");

    }
    //create .init_array
    dyn_item dyn_init_array = dynamic_section_.find_dyn_by_tag(DT_INIT_ARRAY);
    dyn_item dyn_init_array_sz = dynamic_section_.find_dyn_by_tag(DT_INIT_ARRAYSZ);
    if (dyn_init_array.is_valid()
        && dyn_init_array_sz.is_valid()){
        elf_section init_array_section_;
        Elf32_Shdr &header_ = init_array_section_.get_header();
        header_.sh_type = SHT_INIT_ARRAY;
        header_.sh_addr = dyn_init_array.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = dyn_init_array_sz.get_value();
        header_.sh_flags = SHF_ALLOC | SHF_WRITE;
        header_.sh_name = find_string_idx_in_strtab(".init_array");
        header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;

        vec_created_section_.push_back(init_array_section_);
        LOG(DBG, ".init_array section created");
    }

    //create .fini_array
    dyn_item dyn_fini_array = dynamic_section_.find_dyn_by_tag(DT_FINI_ARRAY);
    dyn_item dyn_fini_array_sz = dynamic_section_.find_dyn_by_tag(DT_FINI_ARRAYSZ);
    if (dyn_fini_array.is_valid()
        && dyn_fini_array_sz.is_valid()){
        elf_section fini_array_section_;
        Elf32_Shdr &header_ = fini_array_section_.get_header();
        header_.sh_type = SHT_FINI_ARRAY;
        header_.sh_addr = dyn_fini_array.get_addr();
        header_.sh_offset = header_.sh_addr - calc_VA_FA_gap(header_.sh_addr);
        header_.sh_size = dyn_fini_array_sz.get_value();
        header_.sh_flags = SHF_ALLOC | SHF_WRITE;
        header_.sh_name = find_string_idx_in_strtab(".fini_array");
        header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;

        vec_created_section_.push_back(fini_array_section_);
        LOG(DBG, ".fini_array section created");
    }

    //create dynmamic section
    {
        std::string dyn_segment_string_ = dynamic_section_.get_section_information();
        elf_segment dyn_segment_;
        dyn_segment_.from_string(dyn_segment_string_);

        elf_section dyn_section_;
        Elf32_Shdr &header_ = dyn_section_.get_header();
        header_.sh_name = find_string_idx_in_strtab(".dynamic");
        header_.sh_addr = dyn_segment_.get_header().p_vaddr;
        header_.sh_offset = dyn_segment_.get_header().p_offset;
        header_.sh_size = dyn_segment_.get_header().p_filesz;
        header_.sh_type = SHT_DYNAMIC;
        header_.sh_flags = SHF_WRITE;
        header_.sh_addralign = header_.sh_addr % 4 ? 1 : 4;
        header_.sh_link = 1;
        header_.sh_entsize = sizeof(Elf32_Dyn);

        vec_created_section_.push_back(dyn_section_);
        LOG(DBG, ".dynamic section created");
    }


    //fix symtab size
    return fix_sym_tab_size()
        && fix_sym_item_section_ref();
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
        if (itr.get_header().p_paddr <= section_addr
            && itr.get_header().p_paddr + itr.get_header().p_memsz > section_addr){
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
        std::string null_seperator("\0", 1);
        sh_str_ += null_seperator; //idx = 0
        sh_str_ += (".interp" + null_seperator); //idx = 1
        sh_str_ += (".note.gnu.build-i" + null_seperator);
        sh_str_ += (".dynsym" + null_seperator);
        sh_str_ += (".dynstr" + null_seperator);
        sh_str_ += (".hash" + null_seperator);
        sh_str_ += (".gnu.version" + null_seperator);
        sh_str_ += (".gnu.version_d" + null_seperator);
        sh_str_ += (".gnu.version_r" + null_seperator);
        sh_str_ += (".rel.dyn" + null_seperator);
        sh_str_ += (".rel.plt" + null_seperator);
        sh_str_ += (".text" + null_seperator);
        sh_str_ += (".ARM.extab" + null_seperator);
        sh_str_ += (".ARM.exidx" + null_seperator);
        sh_str_ += (".rodata" + null_seperator);
        sh_str_ += (".fini_array" + null_seperator);
        sh_str_ += (".init_array" + null_seperator);
        sh_str_ += (".dynamic" + null_seperator);
        sh_str_ += (".got" + null_seperator);
        sh_str_ += (".data" + null_seperator);
        sh_str_ += (".bss" + null_seperator);
        sh_str_ += (".comment" + null_seperator);
        sh_str_ += (".note.gnu.gold-ve" + null_seperator);
        sh_str_ += (".ARM.attributes" + null_seperator);
        sh_str_ += (".dynamic" + null_seperator);
        sh_str_ += (".shstrtab" + null_seperator);
    }

    std::string::size_type idx = sh_str_.find(str);
    if (std::string::npos != idx){
        return (int)idx;
    }

    LOG(ERR, "try to find string index in section header string table, but can't find it");
    return -1;
}

bool section_fix::fix_sym_tab_size()
{
    //0. find the end of the .symtab with sym  "_end"
    std::vector<elf_section>::iterator dym_section_itr_ = std::find_if(vec_created_section_.begin(), vec_created_section_.end(), 
        [=](elf_section &item)->bool{
        return (SHT_SYMTAB == item.get_header().sh_type);
    });

    std::vector<elf_section>::iterator dyn_str_section_itr_ = std::find_if(vec_created_section_.begin(), vec_created_section_.end(),
        [=](elf_section &item)->bool{
        return (SHT_STRTAB == item.get_header().sh_type);
    });

    if (dym_section_itr_ != vec_created_section_.end()
        && dyn_str_section_itr_ != vec_created_section_.end()){
        //search symtab until to the symbol _end
        
        std::string dyn_string(file_content_.c_str() + dyn_str_section_itr_->get_header().sh_offset, dyn_str_section_itr_->get_header().sh_size);

        int search_cnt = 0; //max search count = 10000
        Elf32_Sym *sym_start_ = (Elf32_Sym *)(file_content_.c_str() + dym_section_itr_->get_header().sh_offset);
        sym_start_++;
        do 
        {
            try
            {
                Elf32_Word sym_name_off_ = sym_start_->st_name;
                //if (!sym_name_off_){
                //    //found the end
                //    break;
                //}

                if (sym_name_off_ < dyn_string.size()){
                    std::string syn_name = dyn_string.c_str() + sym_name_off_;
                    if (syn_name.empty()){
                        //found the end
                        break;
                    }
                }

            }
            catch (...)
            {
                LOG(ERR, "try search sym table end, but exception occur, give up");
            }

            search_cnt++;
            if (search_cnt > 10000){
                LOG(ERR, "try search sym table end, but now try count > 10000, give up");
                break;
            }
        } while (sym_start_++);

        if (search_cnt > 10000){
            return false;
        }

        dym_section_itr_->get_header().sh_size = (search_cnt + 1) * sizeof(Elf32_Sym);

        LOG(DBG, "found %d symbols", search_cnt);
        return true;
    }

    return false;
}

bool section_fix::fix_sym_item_section_ref()
{
    //0. find the end of the .symtab with sym  "_end"
    std::vector<elf_section>::iterator dym_section_itr_ = std::find_if(vec_created_section_.begin(), vec_created_section_.end(),
        [=](elf_section &item)->bool{
        return (SHT_SYMTAB == item.get_header().sh_type);
    });

    std::vector<elf_section>::iterator dyn_str_section_itr_ = std::find_if(vec_created_section_.begin(), vec_created_section_.end(),
        [=](elf_section &item)->bool{
        return (SHT_STRTAB == item.get_header().sh_type);
    });

    if (dym_section_itr_ != vec_created_section_.end()
        && dyn_str_section_itr_ != vec_created_section_.end()){
        //search symtab until to the symbol _end

        std::string dyn_string(file_content_.c_str() + dyn_str_section_itr_->get_header().sh_offset, dyn_str_section_itr_->get_header().sh_size);

        int search_cnt = 0; //max search count = 10000
        Elf32_Sym *sym_start_ = (Elf32_Sym *)(file_content_.c_str() + dym_section_itr_->get_header().sh_offset);
        do
        {
            try
            {
                Elf32_Word sym_name_off_ = sym_start_->st_name;
                if (sym_name_off_ < dyn_string.size()){
                    std::string syn_name = dyn_string.c_str() + sym_name_off_;
                    sym_start_->st_shndx = calc_addr_section_idx(sym_start_->st_value);
                    struct bit_info{
                        unsigned char sym_info_type : 4;
                        unsigned char sym_info_bind : 4;
                    };
                    bit_info *sym_info_ = (bit_info *)&sym_start_->st_info;
                    if (sym_info_->sym_info_type > 4){ // max = STI_FILE = 4
                        sym_info_->sym_info_type = 2; // STI_FUNC = 2
                    }
                    if (sym_info_->sym_info_bind > 2){ // max = STB_WEAK
                        sym_info_->sym_info_bind = 1; //STB_GLOBAL = 2
                    }

                    if (syn_name.find("_end") != std::string::npos){
                        //found the end
                        break;
                    }
                }

            }
            catch (...)
            {
                LOG(ERR, "try search sym table end, but exception occur, give up");
            }

            search_cnt++;
            if (search_cnt > 10000){
                LOG(ERR, "try search sym table end, but now try count > 10000, give up");
                break;
            }
        } while (sym_start_++);
        return true;
    }

    return false;
}

int section_fix::calc_addr_section_idx(Elf32_Off addr)
{
    return vec_created_section_.size() + 1;

    std::sort(vec_created_section_.begin(), vec_created_section_.end(), 
        [=](elf_section &item1, elf_section &item2)->bool{
        return item1.get_header().sh_addr < item2.get_header().sh_addr;
    });

    for (int i = 0; i < vec_created_section_.size(); i ++){
        elf_section section_ = vec_created_section_[i];
        if (addr >= section_.get_header().sh_addr
            && addr < section_.get_header().sh_addr + section_.get_header().sh_size){
            return i;
        }
    }
    return 0;
}

/******************************************************************************/