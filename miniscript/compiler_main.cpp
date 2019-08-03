#include <iostream>
#include <stdio.h>
#include <string>
#include <ctype.h>
#include <assert.h>

#include <script/miniscript.h>

#include "compiler.h"

static bool run(std::string&& line, int64_t count) {
    if (line.size() && line.back() == '\n') line.pop_back();
    if (line.size() == 0) return false;

    miniscript::NodeRef<CompilerKey> ret;
    double avgcost = 0;
    if (!Compile(line, ret, avgcost)) {
        printf("Cannot compile: %s\n", line.c_str());
        return true;
    }
    printf("%7li %17.10f %5i %s %s\n", (long)count, ret->ScriptSize() + avgcost, (int)ret->ScriptSize(), ret->ToString(COMPILER_CTX).c_str(), line.c_str());
    return true;
}

int main(void) {
    int64_t count = 0;
    do {
        std::string line;
        std::getline(std::cin, line);
        if (!run(std::move(line), count++)) break;
    } while(true);
}
