
SIMULATOR_SRC_DIR=../src/simulator
FUZZER_SRC_DIR=../src/fuzzer
QEMU_FRAMEWORK_SRC_DIR=../src/qemu_framework
HEADER_DIR=../header
LIB_DIR=../lib
OUTPUT_DIR=../bin
gcc -I$HEADER_DIR $SIMULATOR_SRC_DIR/simulator.c $SIMULATOR_SRC_DIR/main.c $QEMU_FRAMEWORK_SRC_DIR/xx.c -Wno-unused-result -Wno-format -ldl -O3 `pkg-config --cflags --libs glib-2.0` -I$LIB_DIR/ihex -I$QEMU_FRAMEWORK_SRC_DIR/ -I$QEMU_FRAMEWORK_SRC_DIR/ -L$LIB_DIR/ihex /usr/local/lib/libihex.so -fPIE -o $OUTPUT_DIR/simulator -lkk_ihex
gcc -I$HEADER_DIR -D DBG $SIMULATOR_SRC_DIR/simulator.c $SIMULATOR_SRC_DIR/main.c $QEMU_FRAMEWORK_SRC_DIR/xx.c -Wno-unused-result -Wno-format -ldl -O3 `pkg-config --cflags --libs glib-2.0` -I$LIB_DIR/ihex -I$QEMU_FRAMEWORK_SRC_DIR/ -I$QEMU_FRAMEWORK_SRC_DIR/ -L$LIB_DIR/ihex /usr/local/lib/libihex.so -fPIE -o $OUTPUT_DIR/simulator_dbg -lkk_ihex
g++ -I$HEADER_DIR $FUZZER_SRC_DIR/iofuzzer.cpp -Wno-unused-result -Wno-format -O3 `pkg-config --cflags --libs glib-2.0` -lpthread -fPIE -o $OUTPUT_DIR/iofuzz
