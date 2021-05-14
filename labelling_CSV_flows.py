import csv
from datetime import datetime
from datetime import timedelta

DAY_STR = [None, "Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

PRINT_STEPS = 3000
DATE_FORMAT_INTERNAL = '%d/%m/%Y %I:%M:%S %p'
DATE_FORMAT_DATASET = '%d/%m/%Y %I:%M:%S %p'
# The CICIDS 2017 dataset was generated in New Brunswick, Canada. Running the CICFlowMeter tool on this data automatically
# converts all timestamps in the data from the timezone of New Brunswick, Canada, to the timezone of the host running
# the CICFlowMeter tool. The TIME_DIFFERENCE attribute specifies the time difference between these two timezones.
# specifically: TIME_DIFFERENCE = {CICFlowMeter host timezone} - {New Brunswick, Canada timezone}
TIME_DIFFERENCE = timedelta(hours=5)

INPUT_DIR = 'UnlabelledDataset/'
OUTPUT_DIR = 'LabelledDataset/'

# Some attack categories rely on transfer of a payload in order to be effective. When a malicious flow belongs to such a
# category but doesn't contain a payload, setting this filter to True will label these flows as "X - Attempted" with "X"
# the original attack class. Setting this filter to False will simply label the flow as part of the attack category.
PAYLOAD_FILTER_ACTIVE = True


# DATE_FORMAT_DATASET = '%d/%m/%Y %H:%M'
# TIME_DIFFERENCE = timedelta(hours=0)


def merge_label(day):
    day_str = DAY_STR[day]  # 3-reorganize
    with open('G:\\Datasets\\CICIDS2017-PCAPs\\2-labeling\\' + day_str + '-WorkingHours.pcap_REVI.csv') as csv_flow:
        spamreader = csv.reader(csv_flow, delimiter=',', quotechar='|')
        next(spamreader)
        total = 0
        with open('G:\\Datasets\\CICIDS2017-PCAPs\\2-labeling\\' + day_str + '-WorkingHours.pcap_SeqInfo.txt',
                  'r') as txt_input:
            with open('G:\\Datasets\\CICIDS2017-PCAPs\\2-labeling\\' + day_str + '-WorkingHours.pcap_SeqInfoLabel.txt',
                      'w') as txt_output:
                for row_seq in txt_input:
                    txt_row = row_seq.split(';')
                    csv_row = next(spamreader)
                    assert (txt_row[0] == csv_row[-1])  # same uid

                    txt_row.insert(1, csv_row[-1])  # insert label into text file
                    txt_output.write(';'.join(txt_row))
                    txt_output.flush()

                    total += 1
    print(day_str + " merged")


def dataset_stat_attack(day, ver='ISCX'):
    day_str = DAY_STR[day]
    col = -1  # if ver == 'ISCX' else -2
    with open(OUTPUT_DIR + day_str + '-WorkingHours.pcap_' + ver + '.csv',
              newline='') as csv_flow:
        spamreader = csv.reader(csv_flow, delimiter=',', quotechar='|')
        next(spamreader)
        total = 0
        all_attacks = {}
        for row in spamreader:
            lbl_attack = row[col]
            if lbl_attack not in all_attacks:
                all_attacks[lbl_attack] = 1
            else:
                all_attacks[lbl_attack] += 1
            total += 1
            # if total % PRINT_STEPS == 0:
            #     print('> ' + str(total))
    print(ver + ' Stat ' + day_str + ':')
    print(all_attacks)
    print('Total: ' + str(total))


# row = a row in the CSV file, corresponding to one flow
# attack_class = String name of the attack class
# Returns a string of the attack class if it passes through the filter
# Returns "X - Attempted" with X the attack_class if the flow is a TCP flow and does not contain any data transfer in
# the forward direction.
# Note that if the payload filter is not active, or the underlying protocol is not TCP, it returns the attack class
# by default.
def payload_filter(row, attack_class):
    # row[10] = total Length of payload bytes in Fwd direction
    # row[5] = Protocol, we only want TCP connections, 6 = TCP
    if PAYLOAD_FILTER_ACTIVE and int(row[5]) == 6:
        if float(row[10]) > 0.0:
            return attack_class
        else:
            return attack_class + " - Attempted"
    else:
        return attack_class


def monday_benign(_):
    return "BENIGN"


def tuesday_ftp_patator(row):
    t_start = datetime.strptime('04/07/2017 09:17:00 AM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('04/07/2017 10:30:00 AM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "FTP-Patator")
    return None


def tuesday_ssh_patator(row):
    t_start = datetime.strptime('04/07/2017 01:00:00 PM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('04/07/2017 04:11:00 PM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "SSH-Patator")
    return None


def wednesday_dos_slowloris(row):
    t_start = datetime.strptime('05/07/2017 02:23:00 AM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('05/07/2017 10:12:59 AM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "DoS slowloris")
    return None


def wednesday_dos_slowhttptest(row):
    t_start = datetime.strptime('05/07/2017 10:13:00 AM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('05/07/2017 10:38:00 AM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "DoS Slowhttptest")
    return None


def wednesday_dos_hulk(row):
    t_start = datetime.strptime('05/07/2017 10:39:00 AM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('05/07/2017 11:09:00 AM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "DoS Hulk")
    return None


def wednesday_dos_goldeneye(row):
    t_start = datetime.strptime('05/07/2017 11:10:00 AM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('05/07/2017 11:23:00 AM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "DoS GoldenEye")
    return None


def wednesday_heartbleed(row):
    t_start = datetime.strptime('05/07/2017 03:11:00 PM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('05/07/2017 03:33:00 PM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.51'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end and row[4] == '444':
        return payload_filter(row, "Heartbleed")
    return None


def thursday_web_attack_brute_force(row):
    t_start = datetime.strptime('06/07/2017 09:10:00 AM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('06/07/2017 10:12:00 AM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "Web Attack - Brute Force")
    return None


def thursday_web_attack_xss(row):
    t_start = datetime.strptime('06/07/2017 10:13:00 AM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('06/07/2017 10:37:00 AM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "Web Attack - XSS")
    return None


def thursday_web_attack_sql_injection(row):
    t_start = datetime.strptime('06/07/2017 10:39:00 AM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('06/07/2017 10:45:00 AM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "Web Attack - Sql Injection")
    return None


def thursday_web_attack_infiltration(row):
    t_start = datetime.strptime('06/07/2017 02:15:00 PM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('06/07/2017 03:50:00 PM', DATE_FORMAT_INTERNAL)
    attacker = '192.168.10.8'
    victim = '205.174.165.73'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "Infiltration")
    return None


def friday_botnet(row):
    t_start = datetime.strptime('07/07/2017 09:30:00 AM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('07/07/2017 12:59:59 PM', DATE_FORMAT_INTERNAL)
    cond_hosts = (row[1] == '205.174.165.73' or row[3] == '205.174.165.73') or (
            row[1] == '192.168.10.17' and row[3] == '52.7.235.158') or (
                         row[1] == '192.168.10.12' and row[3] == '52.6.13.28')
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if t_start <= t_flow <= t_end and cond_hosts and (row[2] == '8080' or row[4] == '8080') and row[5] == '6':
        return payload_filter(row, "Bot")
    return None


def friday_portscan(row):
    t_start = datetime.strptime('07/07/2017 12:30:00 PM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('07/07/2017 03:40:00 PM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return "PortScan"
    return None


def friday_ddos(row):
    t_start = datetime.strptime('07/07/2017 03:40:00 PM', DATE_FORMAT_INTERNAL)
    t_end = datetime.strptime('07/07/2017 04:30:00 PM', DATE_FORMAT_INTERNAL)
    attacker = '172.16.0.1'
    victim = '192.168.10.50'
    t_flow = datetime.strptime(row[6], DATE_FORMAT_DATASET) - TIME_DIFFERENCE
    if row[1] == attacker and row[3] == victim and t_start <= t_flow <= t_end:
        return payload_filter(row, "DDoS")
    return None


def dataset_labeling(day):
    day_str = [None, "Monday", "Tuesday", "Wednesday", "Thursday", "Friday"][day]
    day_filters = [None,
                   [monday_benign],
                   [tuesday_ftp_patator, tuesday_ssh_patator],
                   [wednesday_dos_slowloris, wednesday_dos_slowhttptest, wednesday_dos_hulk, wednesday_dos_goldeneye,
                    wednesday_heartbleed],
                   [thursday_web_attack_brute_force, thursday_web_attack_xss, thursday_web_attack_sql_injection,
                    thursday_web_attack_infiltration],
                   [friday_botnet, friday_portscan, friday_ddos]][day]
    with open(INPUT_DIR + day_str + '-WorkingHours.pcap_Flow.csv',
              newline='') as csv_flow:
        with open(OUTPUT_DIR + day_str + '-WorkingHours.pcap_REVI.csv', 'w',
                  newline='') as csv_revised:
            spamreader = csv.reader(csv_flow, delimiter=',', quotechar='|')
            spamwriter = csv.writer(csv_revised, delimiter=',', quotechar='|')
            header = next(spamreader)
            spamwriter.writerow(header)

            total = 0
            all_attacks = {}
            for row in spamreader:
                lbl = "BENIGN"
                for filter in day_filters:
                    lbl_attack = filter(row)
                    if lbl_attack:
                        lbl = lbl_attack
                        break
                row[-1] = lbl

                if lbl not in all_attacks:
                    all_attacks[lbl] = 1
                else:
                    all_attacks[lbl] += 1

                spamwriter.writerow(row)
                total += 1
                # if total % PRINT_STEPS == 0:
                #     print('> ' + str(total))
    print('REVI Stat ' + day_str + ':')
    print(all_attacks)
    print('Total: ' + str(total))


def show_all_stats():
    # dataset_stat_attack(5, 'ISCX')
    dataset_stat_attack(5, 'REVI')


def label_all_datasets():
    for i in range(1, 6):
        dataset_labeling(i)

    for i in range(1, 6):
        # dataset_stat_attack(i, 'ISCX')
        dataset_stat_attack(i, 'REVI')
        print('\n')


def merge_all_labels():
    for i in range(1, 6):
        merge_label(i)


if __name__ == '__main__':
    label_all_datasets()
    # merge_all_labels()
