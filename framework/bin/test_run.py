import threading
import subprocess
import signal
import time
import os
import multiprocessing
import psutil




def run_fuzz(name,config_file,idx,affinity):
    proc = subprocess.Popen(["./iofuzz", "fuzz", config_file,"./simulator","-corpus","/root/corpus/{}_{}/".format(name,idx)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return proc



def main():
    one_day = 20 * 60 * 60
    runs = 3
    configs = [                                                        
        ("3dprinter","/root/target/3dprinter/fuzzware_config.yml"),
        ("bcn_ffd_ncp","/root/target/bcn_ffd_ncp/fuzzware_config.yml"),
        ("blehci","/root/target/blehci/aidfuzzer_config.yml"),
        ("coord_ncp","/root/target/coord_ncp/fuzzware_config.yml"),
        ("mac_no_beacon_sleep","/root/target/mac_no_beacon_sleep/fuzzware_config.yml"), #
        ("nmea","/root/target/nmea/fuzzware_config.yml"),
        ("nobcn_rfd","/root/target/nobcn_rfd/fuzzware_config.yml"),
        ("qrcode","/root/target/qrcode/fuzzware_config.yml"),
        # ("serial_if_ncp","/root/target/serial_if_ncp/fuzzware_config.yml"),
        ("slip-radio","/root/target/slip-radio/fuzzware_config.yml"),
        ("taulab","/root/target/taulab/fuzzware_config.yml"),
        ("usb_fw_gen","/root/target/usb_fw_gen/fuzzware_config.yml"),
        ("annepro-shine","/root/target/annepro-shine/fuzzware_config.yml"),
        ("bcn_rfd_ncp","/root/target/bcn_rfd_ncp/fuzzware_config.yml"), 
        ("cjson","/root/target/cjson/fuzzware_config.yml"),
        ("ctr_ncp","/root/target/ctr_ncp/fuzzware_config.yml"), #
        ("mp3","/root/target/mp3/fuzzware_config.yml"),
        ("nobcn_ffd_ncp","/root/target/nobcn_ffd_ncp/fuzzware_config.yml"), #
        ("picouart_example1","/root/target/picouart_example1/fuzzware_config.yml"),
        ("sam4l_qtouch","/root/target/sam4l_qtouch/fuzzware_config.yml"),
        #("single_button_ctr_ncp","/root/target/single_button_ctr_ncp/fuzzware_config.yml"),
        ("sms","/root/target/sms/fuzzware_config.yml"),
        # ("tgt_ncp","/root/target/tgt_ncp/fuzzware_config.yml"),
        ("xml","/root/target/xml/fuzzware_config.yml")
    ]
    tasks = []
    for i in range(runs):
        for config in configs:
            tasks.append((config[0],config[1],i))

    while len(tasks) != 0:
        task_runs = []
        for i in range(psutil.cpu_count(logical = False)):
            if len(tasks) != 0:
                task = tasks.pop(0)
                proc = run_fuzz(task[0],task[1],task[2],i)
                task_runs.append(proc)
        time.sleep(one_day)
        for proc in task_runs:
            os.kill(proc.pid, signal.SIGINT)
        for proc in task_runs:
            proc.wait()
        

    

if __name__ == "__main__":
    main()





