/*******************************************************************************
 *  @file      elf_header.h 2017\5\11 9:17:19 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#ifndef ELF_HEADER_A895F373_37CD_4A8E_BD6C_879AA0445273_H__
#define ELF_HEADER_A895F373_37CD_4A8E_BD6C_879AA0445273_H__

#include "elf.h"
#include <string>
/******************************************************************************/

/**
 * The class <code>elf_header</code> 
 *
 */
class elf_header
{
public:
    /** @name Constructors and Destructor*/

    //@{
    /**
     * Constructor 
     */
    elf_header();
    /**
     * Destructor
     */
    ~elf_header();
    //@}
    
public:

    /**
         * @fn  bool elf_header::from_string(const char *str_content);
         *
         * @brief   Initializes elf header from the given string.
         *
         * @param   str_content - string contains the elf header content
         *
         * @return  True if it succeeds, false if it fails.
         */
    bool from_string(std::string str_content);

    /**
         * @fn  std::string elf_header::to_string();
         *
         * @brief   Converts this object to a string.
         *
         * @return  This object as a std::string.
         */
    std::string to_string();


    /**
         * @fn  std::string elf_header::print();
         *
         * @brief   print the elf header as a styled string
         *
         * @return  formated elf header content string
         */
    std::string print();

    /**
         * @fn  int elf_header::size()
         *
         * @brief   get elf header size
         *
         * @return  elf header size
         */
    int size(){ return sizeof(Elf32_Ehdr); }

    /**
         * @fn  Elf32_Ehdr elf_header::get_header()
         *
         * @brief   Gets the orignal header content.
         *
         * @return  The header.
         */
    Elf32_Ehdr &get_header(){ return header_; };
private:

    /**
         * @fn  bool elf_header::is_valid();
         *
         * @brief   check if this elf header is valid after is loaded by from string
         *
         * @return  True if valid, false if not.
         */
    bool is_valid();

    /**
         * @fn  std::string elf_header::type_2_string(Elf32_Half type);
         *
         * @brief   convert elf  image type from integer type to string format.
         *
         * @param   type    The type.
         *
         * @return  elf type in string format.
         */
    std::string type_2_string(Elf32_Half type);
private:
    Elf32_Ehdr header_;
};
/******************************************************************************/
#endif// ELF_HEADER_A895F373_37CD_4A8E_BD6C_879AA0445273_H__
