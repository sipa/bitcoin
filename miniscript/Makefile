HEADERS := ../src/util/vector.h ../src/util/strencodings.h ../src/span.h ../src/util/spanparsing.h ../src/script/script.h ../src/script/miniscript.h miniscript_compiler.h ../src/crypto/common.h ../src/serialize.h ../src/prevector.h ../src/compat/endian.h
SOURCES := ../src/util/strencodings.cpp ../src/util/spanparsing.cpp ../src/script/script.cpp ../src/script/miniscript.cpp miniscript_compiler.cpp

miniscript_compiler: $(HEADERS) $(SOURCES) miniscript_compiler_main.cpp
	g++ -O3 -g0 -Wall -march=native -flto -I../src -I. $(SOURCES) miniscript_compiler_main.cpp -o miniscript_compiler

miniscript.js: $(HEADERS) $(SOURCES) miniscript_compiler_js.cpp
	em++ -O3 -g0 -Wall -std=c++11 -fno-rtti -flto -I../src -I. $(SOURCES) miniscript_compiler_js.cpp -s WASM=1 -s FILESYSTEM=0 -s ENVIRONMENT=web -s DISABLE_EXCEPTION_CATCHING=0 -s EXPORTED_FUNCTIONS='["_miniscript_compile","_malloc","_free"]' -s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap","UTF8ToString"]' -o miniscript.js
