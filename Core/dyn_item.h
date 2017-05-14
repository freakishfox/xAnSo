/*******************************************************************************
 *  @file      dyn_item.h 2017\5\11 20:36:47 $
 *  @author    df
 *  @brief     
 ******************************************************************************/

#ifndef DYN_ITEM_5B5FA2C1_1C4D_4AFD_8487_E88884C88742_H__
#define DYN_ITEM_5B5FA2C1_1C4D_4AFD_8487_E88884C88742_H__

#include "elf.h"
#include <string>
/******************************************************************************/

/**
 * The class <code>dyn_item</code> 
 *
 */
class dyn_item
{
public:
    /** @name Constructors and Destructor*/

    //@{
    /**
     * Constructor 
     */
    dyn_item();
    /**
     * Destructor
     */
    ~dyn_item();
    //@}
    
public:

    /**
         * @fn  bool dyn_item::from_string(std::string str_content);
         *
         * @brief   Initializes dynamic item from the given string.
         *
         * @param   str_content - input string
         *
         * @return  parse operation result
         */
    bool from_string(std::string str_content);

    /**
         * @fn  std::string dyn_item::to_string();
         *
         * @brief   Converts this object to a string.
         *          
         * @return  This object as a std::string.
         */
    std::string to_string();

    /**
         * @fn  std::string dyn_item::print();
         *
         * @brief   print section content in styled format
         *
         * @return  formated style section content
         */
    std::string print();

    /**
         * @fn  int dyn_item::size()
         *
         * @brief   get size of dynamic item
         *
         * @return  item size
         */
    int size(){ return sizeof(Elf32_Dyn); }

    /**
        * @fn  int dyn_item::get_tag()
        *
        * @brief   Gets the tag.
        *
        * @return  The tag.
        */
    Elf32_Sword get_tag(){ return dyn_item_.d_tag; }
    Elf32_Word  get_value(){ return dyn_item_.d_un.d_val; }
    Elf32_Addr get_addr(){ return dyn_item_.d_un.d_ptr; }

    /**
         * @fn  bool dyn_item::is_valid()
         *
         * @brief   Query if this object is valid. 0x12345678 means self define invalid value, init in constructor
         *
         * @return  True if valid, false if not.
         */
    bool is_valid(){ return dyn_item_.d_tag != 0x12345678; }

private:

    /**
         * @fn  std::string dyn_item::tag_2_string(int tag);
         *
         * @brief   convert dynamic item to string
         *
         * @param   tag - tag type
         *
         * @return  tag in string format
         */
    std::string tag_2_string(int tag);

private:
    Elf32_Dyn dyn_item_;
};
/******************************************************************************/
#endif// DYN_ITEM_5B5FA2C1_1C4D_4AFD_8487_E88884C88742_H__
