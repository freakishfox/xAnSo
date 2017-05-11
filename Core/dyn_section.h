/*******************************************************************************
 *  @file      dyn_section.h 2017\5\11 23:13:59 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#ifndef DYN_SECTION_A3C72CD4_8D8B_4985_8C19_1FE84230709F_H__
#define DYN_SECTION_A3C72CD4_8D8B_4985_8C19_1FE84230709F_H__

#include "elf.h"
#include <string>
#include <vector>
#include "dyn_item.h"
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
         * @brief   Initializes dyn section from the given string.
         *
         * @param   str_content - input string
         *
         * @return  True if it succeeds, false if it fails.
         */
    bool from_string(std::string str_content);

    /**
         * @fn  std::string dyn_section::to_string();
         *
         * @brief   Converts this object to a string.
         *
         * @return  This object as a std::string.
         */
    std::string to_string();

    /**
         * @fn  std::string dyn_section::print();
         *
         * @brief   print section main information in styled format
         *
         * @return  styled format content
         */
    std::string print();

    /**
         * @fn  int dyn_section::size()
         *
         * @brief   get dyn sectoin size
         * 
         * @return  section size
         */
    int size(){ return items_.size() * sizeof(dyn_item); }

    /**
         * @fn  int dyn_section::count()
         *
         * @brief   get dyn count in .dynamic section
         *
         * @return  item count
         */
    int count(){ return items_.size(); }

private:
    std::vector<dyn_item> items_;
};
/******************************************************************************/
#endif// DYN_SECTION_A3C72CD4_8D8B_4985_8C19_1FE84230709F_H__
