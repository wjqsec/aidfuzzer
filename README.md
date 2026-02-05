Source code for Usenix Security 2025 paper: AidFuzzer: Adaptive Interrupt-Driven Firmware Fuzzing via Run-Time State Recognition

### Quick start
`
docker pull wjqsec555/aidfuzz
docker run -it wjqsec555/aidfuzz bash
cd ~/xxfuzzer/framework/bin
./iofuzz fuzz /root/target/printer/config.yml ./simulator -corpus  /root/corpus/print_24
`
