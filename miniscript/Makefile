HEADERS := ../src/util/vector.h ../src/util/strencodings.h ../src/span.h ../src/util/spanparsing.h ../src/script/script.h ../src/script/miniscript.h compiler.h ../src/crypto/common.h ../src/serialize.h ../src/prevector.h ../src/compat/endian.h
SOURCES := ../src/util/strencodings.cpp ../src/util/spanparsing.cpp ../src/script/script.cpp ../src/script/miniscript.cpp compiler.cpp

miniscript: $(HEADERS) $(SOURCES) main.cpp
	g++ -O3 -g0 -Wall -march=native -flto -I../src $(SOURCES) main.cpp -o miniscript

miniscript.js: $(HEADERS) $(SOURCES) js_bindings.cpp
	em++ -O3 -g0 -Wall -std=c++11 -fno-rtti -flto -I../src $(SOURCES) js_bindings.cpp -s WASM=1 -s FILESYSTEM=0 -s ENVIRONMENT=web -s DISABLE_EXCEPTION_CATCHING=0 -s EXPORTED_FUNCTIONS='["_miniscript_compile","_miniscript_analyze","_malloc","_free"]' -s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap","UTF8ToString"]' -o miniscript.js
