
# -*- coding: utf-8 -*-

# Android IDA反调试插件，配合Android LKM一起使用，威力惊人

import idaapi
import idautils


class AntiDebug:

    def __init__(self):
        idaapi.msg("<StrongIDA>AntiDebug Module Load...\n")

    # linker调试标志
    def patch_linker_debug_flag(self):

        loaded_modules = idautils.Modules()
        linker_flag = "rtld_db_dlactivity"
        linker_fake_flag = "rtdd_db_dlacticity"

        for module in loaded_modules:
            shall_continue_search_modules = False

            if module.name == "/system/bin/linker":
                idaapi.msg("<StrongIDA>OK, StrongIDA Found Linker, Try Patch...\n")
                for idx in range(module.base, module.base + module.size):

                    memory_buf = idaapi.dbg_read_memory(idx, len(linker_flag))
                    if str(memory_buf) == linker_flag:
                        idaapi.dbg_write_memory(idx, linker_fake_flag)
                        idaapi.refresh_debugger_memory()
                        idaapi.msg("<StrongIDA>Great, StrongIDA Patch Finish~~\n")

                        shall_continue_search_modules = True
                        break

            if shall_continue_search_modules:
                break


class StrongIDA(idaapi.plugin_t):

    flags = idaapi.PLUGIN_UNL

    comment = "IDA反调试插件， 作者：敌法@freakishfox"

    help = ""

    wanted_name = "StrongIDA"

    wanted_hotkey = ""

    def init(self):
        idaapi.msg("StrongIDA Loading...\n")

        anti = AntiDebug()
        anti.patch_linker_debug_flag()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("StrongIDA Called...\n")

    def term(self):
        idaapi.msg("StrongIDA UnLoading...\n")


def PLUGIN_ENTRY():
    return StrongIDA()
