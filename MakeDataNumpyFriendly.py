'''
This Should be run after all CSV files are fully labelled.
The script does two things:
1. It removes flow id, source ip, destination ip, source port, and timestamp as features
2. It converts all labels to numerical labels
'''
import copy
import csv
import pandas as pd
import numpy as np

dataset_directory = 'LabelledDataset'
saved_numpy_name = 'full_dataset_no_artefacts_with_payload_filter.npy'


def importCsvAsDict(path):
    print('Importing from ', path)
    csvfile = csv.DictReader(open(path), delimiter=',')
    return [x for x in csvfile]


def convertToNumericalLabels(flows_list_of_dict):
    print('Relabelling flows')

    label_dictionary = {
        'BENIGN': '0',
        'FTP-Patator': '1',
        'SSH-Patator': '2',
        'DoS GoldenEye': '3',
        'DoS Hulk': '4',
        'DoS Slowhttptest': '5',
        'DoS slowloris': '6',
        'Heartbleed': '7',
        'Web Attack - Brute Force': '8',
        'Web Attack - XSS': '9',
        'Web Attack - Sql Injection': '10',
        'Infiltration': '11',
        'Bot': '12',
        'PortScan': '13',
        'DDoS': '14',
        # IMPORTANT NOTE: For our experiments, we treated all "X - Attempted" flows as BENIGN. If you want to keep the
        # "X - Attempted" flows separate, please change the values corresponding to the keys below
        'FTP-Patator - Attempted' : '0',
        'SSH-Patator - Attempted' : '0',
        'DoS GoldenEye - Attempted' : '0',
        'DoS Hulk - Attempted' : '0',
        'DoS Slowhttptest - Attempted' : '0',
        'DoS slowloris - Attempted' : '0',
        'Heartbleed - Attempted' : '0',
        'Web Attack - Brute Force - Attempted' : '0',
        'Web Attack - XSS - Attempted' : '0',
        'Web Attack - Sql Injection - Attempted' : '0',
        'Infiltration - Attempted' : '0',
        'Bot - Attempted' : '0',
        # Note that PortScan doesn't have any 'Attempted' flows because it doesn't rely on a payload transfer for its
        # effectiveness
        'DDoS - Attempted' : '0'
    }

    for (index, row) in enumerate(flows_list_of_dict):
        current_label = row['Label']
        flows_list_of_dict[index]['Label'] = label_dictionary[current_label]


def listOfDictToNumpyArray(list_of_dict):
    dataframe = pd.DataFrame(list_of_dict)
    numpy_string_array = dataframe.values
    # See point 1 in the description at the top of the file
    trimmed_values = np.concatenate((numpy_string_array[:, 4:6], numpy_string_array[:, 7:]), axis=1)
    return trimmed_values.astype(np.float)


print("monday")
monday_dict = importCsvAsDict(dataset_directory + '/Monday-WorkingHours.pcap_REVI.csv')
convertToNumericalLabels(monday_dict)
monday_numpy_array = listOfDictToNumpyArray(monday_dict)

print("tuesday")
tuesday_dict = importCsvAsDict(dataset_directory + '/Tuesday-WorkingHours.pcap_REVI.csv')
convertToNumericalLabels(tuesday_dict)
tuesday_numpy_array = listOfDictToNumpyArray(tuesday_dict)

print("wednesday")
wednesday_dict = importCsvAsDict(dataset_directory + '/Wednesday-WorkingHours.pcap_REVI.csv')
convertToNumericalLabels(wednesday_dict)
wednesday_numpy_array = listOfDictToNumpyArray(wednesday_dict)

print("thursday")
thursday_dict = importCsvAsDict(dataset_directory + '/Thursday-WorkingHours.pcap_REVI.csv')
convertToNumericalLabels(thursday_dict)
thursday_numpy_array = listOfDictToNumpyArray(thursday_dict)

print("friday")
friday_dict = importCsvAsDict(dataset_directory + '/Friday-WorkingHours.pcap_REVI.csv')
convertToNumericalLabels(friday_dict)
friday_numpy_array = listOfDictToNumpyArray(friday_dict)

full_dataset = np.concatenate((monday_numpy_array, tuesday_numpy_array, wednesday_numpy_array, thursday_numpy_array,
                               friday_numpy_array), axis=0)

print("saving dataset")
np.save('NumpyFriendlyData/' + saved_numpy_name, full_dataset)
