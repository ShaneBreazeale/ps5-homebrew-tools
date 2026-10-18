#pragma once

/* x86 DR7 encoding. Z3 (read-only) cannot be represented. */
struct hwbreak {
    unsigned long long address;
    unsigned int type, length;
    int used;
};

static int hwbreak_valid(unsigned int type, unsigned long long address,
                         unsigned int length)
{
    if(type == 1)
        return length == 1 && address < (1ull << 47);
    if(type != 2 && type != 4)
        return 0;
    return (length == 1 || length == 2 || length == 4 || length == 8) &&
        !(address & (length - 1)) && address < (1ull << 47);
}

static unsigned long long hwbreak_control(const struct hwbreak* bp, int slot)
{
    unsigned int len = bp->length == 8 ? 2 : bp->length == 4 ? 3 : bp->length == 2 ? 1 : 0;
    unsigned int rw = bp->type == 1 ? 0 : bp->type == 2 ? 1 : 3;
    return (1ull << (2 * slot)) | ((unsigned long long)(rw | (len << 2)) << (16 + 4 * slot));
}

static unsigned long long hwbreak_mask(int slot)
{
    return (3ull << (2 * slot)) | (15ull << (16 + 4 * slot));
}
