/*******************************************************************************
 *  @file      dyn_section.h 2017\5\11 20:36:47 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#ifndef DYN_SECTION_5B5FA2C1_1C4D_4AFD_8487_E88884C88742_H__
#define DYN_SECTION_5B5FA2C1_1C4D_4AFD_8487_E88884C88742_H__

#include "elf.h"
#include <string>
/******************************************************************************/

/**
 * The class <code>dyn_section</code> 
 *
 */
class dyn_section
{
public:
    /** @name Constructors and Destructor*/

    //@{
    /**
     * Constructor 
     */
    dyn_section();
    /**
     * Destructor
     */
    ~dyn_section();
    //@}
    
public:

    /**
         * @fn  bool dyn_section::from_string(std::string str_content);
         *
         * @brief   Initializes dynamic item from the given string.
         *
         * @param   str_content - input string
         *
         * @return  parse operation result
         */
    bool from_string(std::string str_content);

    /**
         * @fn  std::string dyn_section::print();
         *
         * @brief   print section content in styled format
         *
         * @return  formated style section content
         */
    std::string print();

    /**
         * @fn  int dyn_section::size()
         *
         * @brief   get size of dynamic item
         *
         * @return  item size
         */
    int size(){ return sizeof(Elf32_Dyn); }

private:

    /**
         * @fn  std::string dyn_section::tag_2_string(int tag);
         *
         * @brief   convert dynamic item to string
         *
         * @param   tag - tag type
         *
         * @return  tag in string format
         */
    std::string tag_2_string(int tag);

private:
    Elf32_Dyn dyn_section_;
};
/******************************************************************************/
#endif// DYN_SECTION_5B5FA2C1_1C4D_4AFD_8487_E88884C88742_H__
