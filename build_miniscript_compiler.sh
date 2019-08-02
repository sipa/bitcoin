#!/bin/sh

g++ -O3 -g0 -Wall -march=native -flto -Isrc src/{util/{strencodings,spanparsing},script/{script,miniscript{,_compiler{,_main}}}}.cpp -o miniscript_compiler
