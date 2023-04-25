gcc  simulator.c runner.c xx.c -Wno-unused-result -Wno-format -ldl -O3 `pkg-config --cflags --libs glib-2.0` -o simulator
g++ iofuzzer.cpp -Wno-unused-result -Wno-format -O3 `pkg-config --cflags --libs glib-2.0` -lpthread -o iofuzz
