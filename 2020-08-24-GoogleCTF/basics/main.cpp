#include "obj_dir/Vcheck.h"

#include <iostream>
#include <memory>

int main(int argc, char *argv[]) {
    Verilated::commandArgs(argc, argv);
    std::cout << "Enter password:" << std::endl;
    auto check = std::make_unique<Vcheck>();

    for (int i = 0; i < 100 && !check->open_safe; i++) {
        int c = fgetc(stdin);
        if (c == '\n' || c < 0) break;
        check->data = c & 0x7f;
        check->clk = false;
        check->eval();
        check->clk = true;
        check->eval();
    }
    if (check->open_safe) {
        std::cout << "CTF{real flag would be here}" << std::endl;
    } else {
        std::cout << "=(" << std::endl;
    }
    return 0;
}

