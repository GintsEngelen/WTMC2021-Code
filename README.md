# Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study

This repository contains the code used for our [paper](https://downloads.distrinet-research.be/WTMC2021/Resources/Submission.pdf).  
The code performs the labelling and benchmarking for the [CICIDS 2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
 after it has been processed by [our modified version of the CICFlowMeter tool](https://github.com/GintsEngelen/CICFlowMeter). 
Note that all of this is *research code*.

If you use the code in this repository, please cite our paper:

            @INPROCEEDINGS{Engelen2021Troubleshooting,
            author={Engelen, Gints and Rimmer, Vera and Joosen, Wouter},
            booktitle={2021 IEEE European Symposium on Security and Privacy Workshops (EuroS\&PW)},
            title={Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study},
            year={2021},
            volume={},
            number={},
            pages={},
            doi={}}

An extended documentation of our paper can be found [here](https://downloads.distrinet-research.be/WTMC2021/).

##How to use this repository

First, head over to the website of the [CICIDS 2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html) and download 
the raw version of the dataset (PCAP file format). There are 5 files in total, one for each day. 

Then, run our [our modified version of the CICFlowMeter tool](https://github.com/GintsEngelen/CICFlowMeter) on the data
obtained in the previous step:
 
1. Start the CICFlowMeter tool
2. Under the "NetWork" menu option, select "Offline"
3. For "Pcap dir", choose the directory containing the 5 PCAP files of the CICIDS 2017 dataset
4. For "Output dir", choose the "UnlabelledDataset" directory of this WTCM2021-Code project.
5. Keep the default values for the "Flow TimeOut" and "Activity Timeout" parameters (120000000 and 5000000 respectively)

This will generate 5 CSV files with the flows extracted from the raw PCAP files. 

After this, verify the `TIME_DIFFERENCE`, `INPUT_DIR`, `OUTPUT_DIR` and `PAYLOAD_FILTER_ACTIVE` attributes in the 
`labelling_CSV_flows.py` script, and then run it (no need to specify any command-line options). This will label all the 
flows in the CSV files generated by the CICFlowMeter tool.

Then, run the `MakeDataNumpyFriendly.py` script, which will convert the labelled CSV files into a single numpy array. 
Note that, in our experiments, we chose to relabel all "Attempted" flows as BENIGN. If you wish to keep them separate, 
make sure to change the numerical labels in the `convertToNumericalLabels(flows_list_of_dict)` function.

Finally, run the `Benchmarking_RF.py` script to perform benchmarking on the dataset using a Random Forest classifier. 
Random seeds and various other options can be specified in the first few lines of the script. 