int elf_data = 7;

static int private_helper(int value)
{
    return value + 1;
}

int public_helper(int value)
{
    return private_helper(value) * 2;
}

int main(void)
{
    return public_helper(elf_data) == 16 ? 0 : 1;
}
