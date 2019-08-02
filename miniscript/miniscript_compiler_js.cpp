#include <string>

#include <script/miniscript.h>
#include <miniscript_compiler.h>

namespace {

void Output(const std::string& str, char* out, int outlen) {
    int maxlen = std::min<int>(outlen - 1, str.size());
    memcpy(out, str.c_str(), maxlen);
    out[maxlen] = 0;
}

}

extern "C" {

void miniscript_compile(const char* desc, char* descout, int descoutlen, char* costout, int costoutlen) {
    try {
        std::string str(desc);
        str.erase(str.find_last_not_of(" \n\r\t") + 1);
        miniscript::NodeRef<CompilerKey> ret;
        double avgcost;
        if (!Compile(str, ret, avgcost)) {
            Output("[compile error]", descout, descoutlen);
            Output("[compile error]", costout, costoutlen);
            return;
        }
        Output(ret->ToString(COMPILER_CTX), descout, descoutlen);
        std::string coststr = std::to_string(ret->ScriptSize()) + " bytes script + " + std::to_string(avgcost) + " bytes input = " + std::to_string(ret->ScriptSize() + avgcost) + " bytes";
        Output(coststr, costout, costoutlen);
    } catch (const std::exception& e) {
        Output("[exception: " + std::string(e.what()) + "]", descout, descoutlen);
    }
}

}
