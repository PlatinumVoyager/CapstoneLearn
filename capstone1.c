#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

// raw binary code to disassemble
#define CODE_X86 "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int main(void)
{
    csh handle;

    cs_insn *insn; // points to memory containing all disassembled instructions
    size_t count; // number of instructions stored from cs_disasm()

    /* 
    (hardware arch, hardware mode, pointer to a handle)
    disassemble 64 bit code for the x86 arch 
    */
    if (cs_open(CS_ARCH_X86, CS_MODE_64 + CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, "FAILED: cs_open()\n");
        return EXIT_FAILURE;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // 3 = CS_OPT_ON

    /* disassemble the binary code using the handle from cs_open()
     cs_disasm(handle, binary code to be disasm, length)
     0x1000 = the addr of the first instruction (for looks only?)
     0 = disassemble until there is no more code or it
              encounters a broken instruction, can be set to "1" to only get the first instruction. It can be set to x to get x number
              of instructions
     &insn = used to extract disassembled instructions 
     cs_disasm() result is the number of instructions disassembled
            successfully
    */

    count = cs_disasm(handle, CODE_X86, sizeof(CODE_X86) - 1, 0x1000, 2, &insn);
    
    // check if there are actually any disassembled instructions
    if (count > 0)
    {
        size_t j;

        for (j = 0; j < count; j++)
        {
            printf("0x%"PRIx64": <%d>\t%s\t\t%s\n", insn[j].address, insn[j].id, insn[j].mnemonic,
                    insn[j].op_str);
        }

        // free memory allocated to cs_disasm() used to store <count> instructions
        cs_free(insn, count);

    } else {
        printf("ERR: Failed to disassemble give code!\n");
    }

    cs_close(&handle); // close API handle

    return 0;
}