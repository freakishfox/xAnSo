/*******************************************************************************
 *  @file      elf_segment.h 2017\5\11 19:05:50 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#ifndef ELF_SEGMENT_3E338771_FA63_4EA5_901D_3EA3626BFA54_H__
#define ELF_SEGMENT_3E338771_FA63_4EA5_901D_3EA3626BFA54_H__

/******************************************************************************/
#include "elf.h"
#include <string>
/**
 * The class <code>elf_segment</code> 
 *
 */
class elf_segment
{
public:
    /** @name Constructors and Destructor*/

    //@{
    /**
     * Constructor 
     */
    elf_segment();
    /**
     * Destructor
     */
    ~elf_segment();
    //@}
    
public:

    /**
         * @fn  bool elf_segment::from_string(std::string str_content);
         *
         * @brief   Initializes program header from the given string
         *
         * @param   str_content - input string
         *
         * @return  True if it succeeds, false if it fails.
         */
    bool from_string(std::string str_content);

    /**
         * @fn  std::string elf_segment::print();
         *
         * @brief   print the section header in styled format string
         *
         * @return  section content in styled format
         */
    std::string print();

    /**
         * @fn  int elf_segment::size()
         *
         * @brief   get program header size
         *
         * @return  header size
         */
    int size(){ return sizeof(Elf32_Phdr); }

    /**
         * @fn  Elf32_Phdr elf_segment::get_header()
         *
         * @brief   Gets the header.
         *
         * @return  The header.
         */
    Elf32_Phdr get_header(){ return header_; }

private:
    Elf32_Phdr header_;
};
/******************************************************************************/
#endif// ELF_SEGMENT_3E338771_FA63_4EA5_901D_3EA3626BFA54_H__
