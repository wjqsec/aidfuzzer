
import json
import matplotlib.pyplot as plt
import argparse
import os
import re

day_seconds = 24 * 60 * 60


def append_first_last_plot(x,y):
    if len(x) != 0 and x[-1] < day_seconds:
        x.append(day_seconds)
        y.append(y[-1])
    return x,y

def get_fuzzware_cov(filename):
    if filename == "":
        return [],[]
    x = []
    y = []

    with open(filename,"r") as f:
        for line in f.readlines():
            if "#" in line:
                continue
            tmp = re.findall(r'\d+',line)
            x.append(int(tmp[0]))
            y.append(int(tmp[1]))
    
    return append_first_last_plot(x,y)    


def get_hoedur_cov(filename):
    if filename == "":
        return [],[]
    x = []
    y = []
    with open(filename,"r") as f:
        json_object = json.loads(f.read())
        for point in json_object["coverage_translation_blocks"]:
            if int(point["x"]) > day_seconds:
                break
            x.append(int(point["x"]))
            y.append(int(point["y"]))
    return append_first_last_plot(x,y)   




def get_xx_second(line):
    return int(line.split("[")[1].split("]")[0])
def get_xx_bbl(line):
    return int(line.split("bbl:")[1].split(" ")[0])
def get_xx_cov(filename):
    if filename == "":
        return [],[]
    x = []
    y = []
    with open(filename,"r") as f:
        first_line = f.readline()
        start_second = get_xx_second(first_line)
        for line in f.readlines():
            x.append(get_xx_second(line) - start_second)
            y.append(get_xx_bbl(line))
    return append_first_last_plot(x,y)



def main():
    parser = argparse.ArgumentParser(description="plot coverage",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-f", "--fuzzware", help="fuzzware csv file", default="")
    parser.add_argument("-e", "--hoedur",  help="hoedur plot file", default="")
    parser.add_argument("-x", "--xx",  help="xx log file", default="")
    parser.add_argument("-o", "--output", help="output dir", default="./cov_plot/")
    args = parser.parse_args()

    fuzzware_x, fuzzware_y = get_fuzzware_cov(args.fuzzware)
    hoedur_x , hoedur_y = get_hoedur_cov(args.hoedur)
    xx_x, xx_y = get_xx_cov(args.xx)


    plt.plot(xx_x, xx_y,label="aid")
    plt.plot(fuzzware_x, fuzzware_y,label="fuzzware")
    plt.plot(hoedur_x, hoedur_y,label="hoedur")

    plt.ylim(ymin=0)
    plt.xlim(xmin=0,xmax = day_seconds)
    
    plt.xlabel('Time (seconds)')
    plt.ylabel('Value')
    plt.title('Data Plot')

    
    plt.savefig(args.output, format="pdf")

if __name__ == '__main__':
    main()
