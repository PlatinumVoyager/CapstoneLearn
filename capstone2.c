#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#define CODE_X86 "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int main(void)
{
    csh handle;

    cs_insn *inst_set;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64 + CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, "cs_open()\n");
        return -1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    count = cs_disasm(handle, CODE_X86, sizeof(CODE_X86) - 1, 0x1000, 0, &inst_set);
    if (count > 0)
    {
        int n;
        size_t j;

        for (j = 0; j < count; j++)
        {
            cs_insn *i = &(inst_set[j]);
            if (i->id != X86_INS_PUSH && i->id != X86_INS_MOV)
            {
                fprintf(stderr, "Couldnt find PUSH and MOV instructions within x86 disassembly!\n");
                exit(-1);
            }

            // continue
            printf("0x%"PRIx64":\t%s\t\t%s // inst-mnem: %s\n", i->address, i->mnemonic, i->op_str,
                    cs_insn_name(handle, i->id)); // cs_insn_name() = mov, jmp, etc.

            cs_detail *detail = i->detail;
            if (detail->regs_read_count > 0)
            {
                printf("Implicit registers read: ");
                for (n = 0; n < detail->regs_read_count; n++)
                {
                    printf("%s ", cs_reg_name(handle, detail->regs_read[n]));
                }

                printf("\n");
            }

            if (detail->groups_count > 0)
            {
                printf("\tThis instruction belongs to groups: ");
                for (n = 0; n < detail->groups_count; n++)
                {
                    printf("%u ", detail->groups[n]);
                }

                printf("\n");
            }

            // cs_free(i, count);
        }

        cs_free(inst_set, count);
    }

    cs_close(&handle);

    return 0;
}