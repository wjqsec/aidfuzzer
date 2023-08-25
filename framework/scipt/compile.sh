
SIMULATOR_SRC_DIR=../src/simulator
SIMULATOR_BIN_DIR=../../qemu-7.2.0/build
FUZZER_SRC_DIR=../src/fuzzer
QEMU_FRAMEWORK_SRC_DIR=../src/qemu_framework
HEADER_DIR=../header
LIB_DIR=../lib
OUTPUT_DIR=../bin
clang -I$HEADER_DIR \
$SIMULATOR_SRC_DIR/simulator.c \
$SIMULATOR_SRC_DIR/main.c \
$QEMU_FRAMEWORK_SRC_DIR/xx.c \
-ldl -O3 `pkg-config --cflags --libs glib-2.0` -I$LIB_DIR/ihex -I$QEMU_FRAMEWORK_SRC_DIR/  -L$LIB_DIR/ihex  -fPIE -o $OUTPUT_DIR/simulator -lkk_ihex $SIMULATOR_BIN_DIR/libqemu-system-arm.so

clang -I$HEADER_DIR -D DBG \
$SIMULATOR_SRC_DIR/simulator.c \
$SIMULATOR_SRC_DIR/main.c \
$QEMU_FRAMEWORK_SRC_DIR/xx.c \
-ldl -O3 `pkg-config --cflags --libs glib-2.0` -I$LIB_DIR/ihex -I$QEMU_FRAMEWORK_SRC_DIR/  -L$LIB_DIR/ihex  -fPIE -o $OUTPUT_DIR/simulator_dbg -lkk_ihex $SIMULATOR_BIN_DIR/libqemu-system-arm.so

clang++ -I$HEADER_DIR \
$FUZZER_SRC_DIR/iofuzzer.cpp \
$FUZZER_SRC_DIR/queue_entry.cpp \
$FUZZER_SRC_DIR/simulator.cpp \
$FUZZER_SRC_DIR/stream_loader.cpp \
$FUZZER_SRC_DIR/mutator.cpp \
$FUZZER_SRC_DIR/stream.cpp \
$FUZZER_SRC_DIR/model.cpp \
-O3 `pkg-config --cflags --libs glib-2.0` -lpthread -lrt -fPIE -o $OUTPUT_DIR/iofuzz
