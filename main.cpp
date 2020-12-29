#include <common/log.h>
#include <common/cmdline.h>
#include <common/utils/process.h>
#include <elfio/elfio.hpp>
#include <syscall/do_syscall.h>
#include <syscall.h>
#include <asm/prctl.h>

typedef int (*PFN_RUN)(const char *command);
typedef int (*PFN_ENSURE)();
typedef void (*PFN_RELEASE)(int);

constexpr auto PYTHON = "bin/python";
constexpr auto PYTHON_LIBRARY = "libpython";

int main(int argc, char ** argv) {
    cmdline::parser parse;

    parse.add<std::string>("source", 's', "python source file", true, "");
    parse.parse_check(argc, argv);

    auto pid = getpid();
    auto source = parse.get<std::string>("source");

    CProcessMap processMap;

    if (
            !CProcess::getFileMemoryBase(pid, PYTHON_LIBRARY, processMap) &&
            !CProcess::getFileMemoryBase(pid, PYTHON, processMap)
            ) {
        LOG_ERROR("find target library failed");
        return 0;
    }

    LOG_INFO("find target library: 0x%lx -> %s", processMap.start, processMap.file.c_str());

    ELFIO::elfio reader;

    if (!reader.load(processMap.file)) {
        LOG_ERROR("open elf failed: %s", processMap.file.c_str());
        return 0;
    }

    auto it = std::find_if(
            reader.sections.begin(),
            reader.sections.end(),
            [](const auto& s) {
                return s->get_type() == SHT_DYNSYM;
            });

    if (it == reader.sections.end()) {
        LOG_ERROR("can't find symbol section");
        return 0;
    }

    unsigned baseAddress = reader.get_type() == ET_EXEC ? 0 : processMap.start;

    PFN_ENSURE pfnEnsure = nullptr;
    PFN_RUN pfnRun = nullptr;
    PFN_RELEASE pfnRelease = nullptr;

    ELFIO::symbol_section_accessor symbols(reader, *it);

    for (ELFIO::Elf_Xword i = 0; i < symbols.get_symbols_num(); i++) {
        std::string name;
        ELFIO::Elf64_Addr value = 0;
        ELFIO::Elf_Xword size = 0;
        unsigned char bind = 0;
        unsigned char type = 0;
        ELFIO::Elf_Half section = 0;
        unsigned char other = 0;

        if (!symbols.get_symbol(i, name, value, size, bind, type, section,other)) {
            LOG_ERROR("get symbol %lu failed", i);
            return 0;
        }

        if (name == "PyGILState_Ensure")
            pfnEnsure = (PFN_ENSURE)(baseAddress + value);
        else if (name == "PyRun_SimpleString")
            pfnRun = (PFN_RUN)(baseAddress + value);
        else if (name == "PyGILState_Release")
            pfnRelease = (PFN_RELEASE)(baseAddress + value);
    }

    if (!pfnEnsure || !pfnRun || !pfnRelease) {
        LOG_ERROR("can't find python functions");
        return 0;
    }

    LOG_INFO("ensure func: %p run func: %p release func: %p", pfnEnsure, pfnRun, pfnRelease);

    unsigned long fs = 0;
    char *FS = getenv("FS");

    if (!FS) {
        LOG_ERROR("get fs environment variable failed");
        return 0;
    }

    if (!CStringHelper::toNumber(FS, fs, 16)) {
        LOG_ERROR("parse environment variable failed");
        return 0;
    }

    LOG_INFO("set fs: 0x%lx", fs);

    if (do_syscall(SYS_arch_prctl, ARCH_SET_FS, fs) != 0) {
        LOG_ERROR("set fs failed");
        return 0;
    }

    int state = pfnEnsure();
    pfnRun(source.c_str());
    pfnRelease(state);

    do_syscall(SYS_exit, 0);

    return 0;
}
