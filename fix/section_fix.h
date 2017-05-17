/*******************************************************************************
 *  @file      section_fix.h 2017\5\12 19:46:24 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#ifndef SECTION_FIX_CF78F56C_58E1_4F6D_B103_CA85BDF6C2B8_H__
#define SECTION_FIX_CF78F56C_58E1_4F6D_B103_CA85BDF6C2B8_H__

/******************************************************************************/
#include "Core/elf_header.h"
#include "Core/elf_segment.h"
#include "Core/dyn_section.h"
#include "Core/elf_section.h"

#include <string>
#include <vector>
/**
 * The class <code>section_fix</code> 
 *
 */
class section_fix
{
public:
    /** @name Constructors and Destructor*/

    //@{
    /**
     * Constructor 
     */
    section_fix();
    /**
     * Destructor
     */
    ~section_fix();
    //@}
    
public:

    /**
         * @fn  bool section_fix::fix(std::string file);
         *
         * @brief   Fixes the given elf file corrupt sections
         *
         * @param   src_file   - The elf file.
         *
         * @return  True if it succeeds, false if it fails.
         */
    bool fix(std::string src_file);

    /**
         * @fn  bool section_fix::save_as(std::string file);
         *
         * @brief   Saves the fix result to another file
         *
         * @param   dst_file    The file.
         *
         * @return  True if it succeeds, false if it fails.
         */
    bool save_as(std::string dst_file);

private:

    /**
         * @fn  bool section_fix::pre_load();
         *
         * @brief   pre load dynamic sections and pt_load sections
         *
         * @return  True if it succeeds, false if it fails.
         */
    bool pre_load();

    /**
         * @fn  bool section_fix::first_create_sections();
         *
         * @brief   just create sections with information from .dynamic section, then we fix it
         *
         * @return  True if it succeeds, false if it fails.
         */
    bool first_create_sections();

    /**
         * @fn  bool section_fix::fix_sym_tab_size();
         *
         * @brief   fix symtab size by search the symtab content until to the _end symbol
         *
         * @return  True if it succeeds, false if it fails.
         */
    bool fix_sym_tab_size();

    /**
         * @fn  bool section_fix::fix_sym_item_section_ref();
         *
         * @brief   adjust sym item section ref
         *
         * @return  True if it succeeds, false if it fails.
         */
    bool fix_sym_item_section_ref();

    /**
         * @fn  int section_fix::calc_offset_section_idx(Elf32_Off offset);
         *
         * @brief   Calculates which section is the offset should be.
         *
         * @param   offset  The offset.
         *
         * @return  The calculated offset section index.
         */
    int calc_addr_section_idx(Elf32_Off offset);

    /**
         * @fn  int section_fix::calc_VA_FA_gap(Elf32_Addr section_addr);
         *
         * @brief   Calculates the address gap betwwen virtual address and file offset
         *
         * @param   section_addr    The section address.
         *
         * @return  The calculated variable arguments fa gap.
         */
    int calc_VA_FA_gap(Elf32_Addr section_addr);

    /**
         * @fn  int section_fix::find_string_idx_in_strtab(std::string str);
         *
         * @brief   Searches for the first string index in strtab.
         *
         * @param   str The string.
         *
         * @return  The found string index in strtab.
         */
    int find_string_idx_in_strtab(std::string str);
private:
    std::string file_content_; //whole file content

private:
    //find pt_load, pt_dynamic
    std::vector<elf_segment> vec_load_; //save pt_load segements
    dyn_section dynamic_section_; //save .dynamic section

    //created sections
    std::vector<elf_section> vec_created_section_;

    //string used to create .shstrtab
    std::string sh_str_;
};
/******************************************************************************/
#endif// SECTION_FIX_CF78F56C_58E1_4F6D_B103_CA85BDF6C2B8_H__
