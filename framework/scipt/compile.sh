
EXAMPLE_SRC_DIR=../src/example
SIMULATOR_BIN_DIR=../../qemu-7.2.0/build
QEMU_FRAMEWORK_SRC_DIR=../src/qemu_framework
HEADER_DIR=../header
LIB_DIR=../lib
OUTPUT_DIR=../bin
gcc -I$HEADER_DIR $EXAMPLE_SRC_DIR/blehci.c $QEMU_FRAMEWORK_SRC_DIR/xx.c -Wno-unused-result -Wno-format -ldl -O3 `pkg-config --cflags --libs glib-2.0` -I$LIB_DIR/ihex -I$QEMU_FRAMEWORK_SRC_DIR/ -I$QEMU_FRAMEWORK_SRC_DIR/ -L$LIB_DIR/ihex /usr/local/lib/libihex.so -fPIE -o $OUTPUT_DIR/simulator -lkk_ihex $SIMULATOR_BIN_DIR/libqemu-system-arm.so