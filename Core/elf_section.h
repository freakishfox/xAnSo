/*******************************************************************************
 *  @file      elf_section.h 2017\5\11 17:35:21 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#ifndef ELF_SECTION_0586B544_8DB2_4341_B7AC_8FD436EC9F52_H__
#define ELF_SECTION_0586B544_8DB2_4341_B7AC_8FD436EC9F52_H__

#include "elf.h"
#include <string>
/******************************************************************************/

/**
 * The class <code>elf_section</code> 
 *
 */
class elf_section
{
public:
    /** @name Constructors and Destructor*/

    //@{
    /**
     * Constructor 
     */
    elf_section();
    /**
     * Destructor
     */
    ~elf_section();
    //@}
    
public:

    /**
         * @fn  bool elf_section::from_string(std::string str_content);
         *
         * @brief   Initializes this section  header from the given string.
         *
         * @param   str_content - input string
         *
         * @return  True if it succeeds, false if it fails.
         */
    bool from_string(std::string str_content);

    /**
         * @fn  std::string elf_section::to_string();
         *
         * @brief   Converts this header to a string.
         *
         * @return  This header as a std::string.
         */
    std::string to_string();

    /**
         * @fn  std::string elf_section::print();
         *
         * @brief   print the section header
         *
         * @return  styled section header string
         */
    std::string print();

    /**
         * @fn  int elf_section::size()
         *
         * @brief   get section header size
         *
         * @return  header size
         */
    int size(){ return sizeof(Elf32_Shdr); }

    /**
         * @fn  Elf32_Shdr elf_section::&get_header()
         *
         * @brief   Gets the header content reference, so header_ may be modified
         *
         * @return  The header.
         */
    Elf32_Shdr &get_header(){ return header_; }

private:
    Elf32_Shdr header_;
};
/******************************************************************************/
#endif// ELF_SECTION_0586B544_8DB2_4341_B7AC_8FD436EC9F52_H__
