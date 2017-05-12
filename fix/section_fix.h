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

private:
    std::string file_content_; //whole file content

private:
    //find pt_load, pt_dynamic
    std::vector<elf_segment> vec_load_; //save pt_load segements
    dyn_section dynamic_section_; //save .dynamic section


};
/******************************************************************************/
#endif// SECTION_FIX_CF78F56C_58E1_4F6D_B103_CA85BDF6C2B8_H__
