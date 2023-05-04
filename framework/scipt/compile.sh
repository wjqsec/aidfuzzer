
SRC_DIR=../src
LIB_DIR=../lib
OUTPUT_DIR=../bin
gcc  $SRC_DIR/simulator.c $SRC_DIR/runner.c $SRC_DIR/xx.c -Wno-unused-result -Wno-format -ldl -O3 `pkg-config --cflags --libs glib-2.0` -I$LIB_DIR/ihex -L$LIB_DIR/ihex /usr/local/lib/libihex.so -fPIE -o $OUTPUT_DIR/simulator -lkk_ihex
g++  $SRC_DIR/iofuzzer.cpp -Wno-unused-result -Wno-format -O3 `pkg-config --cflags --libs glib-2.0` -lpthread -fPIE -o $OUTPUT_DIR/iofuzz
