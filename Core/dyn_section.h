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
#include "elf_section.h"
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
         * @fn  void dyn_section::save_section_information(std::string section_content);
         *
         * @brief   Saves dynamic section information.
         *
         * @param   section_content The section content.
         */
    void save_section_information(std::string section_content);

    /**
         * @fn  elf_section dyn_section::get_section_information();
         *
         * @brief   Gets the section format of the dynamic section.
         *
         * @return  The section.
         */
    std::string get_section_information();

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

public:

    /**
         * @fn  dyn_item dyn_section::find_dyn_by_tag(int tag);
         *
         * @brief   Searches for the dynamic item by tag.
         *
         * @param   tag - the input tag to search
         *
         * @return  The found dynamic by tag.
         */
    dyn_item find_dyn_by_tag(int tag);

private:
    //items in the .dynamic section
    std::vector<dyn_item> items_;

    //dynamic section
    std::string section_content_;
};
/******************************************************************************/
#endif// DYN_SECTION_A3C72CD4_8D8B_4985_8C19_1FE84230709F_H__
