
import json
import matplotlib.pyplot as plt
import argparse
import os
import re
from dataset import *
from itertools import chain
          



day_seconds = 24 * 60 * 60


def append_first_last_plot(x,y):
    if len(x) != 0 and x[-1] < day_seconds:
        x.append(day_seconds)
        y.append(y[-1])
    if len(x) != 0 and x[0] != 0:
        x.insert(0,0)
        y.insert(0,0)
    return x,y


def get_min_max_mediand(xs,ys):
    max_y = []
    min_y = []
    median_y = []
    x_ax = []
    for x in xs:
        x_ax = list(set([*x_ax,*x]))
    x_ax.sort()
    for i in range(len(x_ax)):
        for j in range(len(xs)):
            if x_ax[i] not in xs[j]:
                ys[j].insert(i,ys[j][i-1])


    for i in range(len(x_ax)):
        tmp_v = []
        for j in range(len(ys)):
            tmp_v.append(ys[j][i])
        
        tmp_v.sort()
        max_y.append(tmp_v[-1])
        min_y.append(tmp_v[0])
        median_y.append(tmp_v[int(len(tmp_v) / 2)])

    return x_ax,max_y,min_y,median_y
        
                
    


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
            if x[-1] == int(tmp[0]):
                x.pop()
                y.pop() 
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
            if len(x) != 0 and x[-1] == int(point["x"]):
                x.pop()
                y.pop()
            x.append(int(point["x"]))
            y.append(int(point["y"]))
    return append_first_last_plot(x,y)   



def plot_one(axe,name, fuzzware_inputs_files, hoedur_inputs_files, aid_inputs_files):
    fuzzware_xs = []
    fuzzware_ys = []

    hoedur_xs = []
    hoedur_ys = []

    aid_xs = []
    aid_ys = []

    for i in fuzzware_inputs_files:
        x,y = get_fuzzware_cov(i)
        fuzzware_xs.append(x)
        fuzzware_ys.append(y)
    for i in hoedur_inputs_files:
        x,y = get_hoedur_cov(i)
        hoedur_xs.append(x)
        hoedur_ys.append(y)
    for i in aid_inputs_files:
        x,y = get_fuzzware_cov(i)
        aid_xs.append(x)
        aid_ys.append(y)
    
    # fuzzware_x, fuzzware_max,fuzzware_min, fuzzware_median = get_min_max_mediand(fuzzware_xs,fuzzware_ys)
    hoedur_x , hoedur_max, hoedur_min , hoedur_median = get_min_max_mediand(hoedur_xs,hoedur_ys)
    # aid_x, aid_max, aid_min, aid_median = get_min_max_mediand(aid_xs,aid_ys)
    
    # axe.plot(fuzzware_x,fuzzware_median)
    # axe.fill_between(fuzzware_x,fuzzware_min,fuzzware_max)

    axe.plot(hoedur_x,hoedur_median)
    axe.fill_between(hoedur_x,hoedur_min,hoedur_max,alpha=0.2)

    # axe.plot(aid_x,aid_median)
    # axe.fill_between(aid_x,aid_min,aid_max)
        

    

def main():
    parser = argparse.ArgumentParser(description="plot coverage",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-o", "--output", help="output file")
    args = parser.parse_args()

    fig, axs = plt.subplots(nrows=1, ncols=1)

    hh = ["/home/w/hd/paper_data/iofuzzer/plot/json/TARGET-aid-fuzzer-3dprinter-FUZZER-hoedur-RUN-{}-DURATION-1d-MODE-fuzzware.json".format(str(r).zfill(2)) for r in range(1,10)]
    plot_one(axs,"xx", [], hh, [])

    
    plt.savefig(args.output, format="pdf")

if __name__ == '__main__':
    main()
