# %%

# https://stackoverflow.com/questions/48484807/training-a-decision-tree-using-id3-algorithm-by-sklearn
# https://scikit-learn.org/stable/modules/tree.html#tree
# https://medium.com/@mohtedibf/indepth-parameter-tuning-for-decision-tree-6753118a03c3
# https://medium.com/datadriveninvestor/tree-algorithms-id3-c4-5-c5-0-and-cart-413387342164
# https://scikit-learn.org/stable/modules/cross_validation.html
import json

import matplotlib
from datetime import datetime
import pandas as pd, numpy as np
import math
from sklearn.model_selection import cross_val_predict, KFold, cross_val_score, train_test_split, learning_curve, \
    cross_validate
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, precision_score, \
    make_scorer, recall_score, precision_recall_fscore_support
from sklearn.preprocessing import MinMaxScaler, minmax_scale, scale
import matplotlib.pyplot as plt
from copy import deepcopy
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier


DITCH_DEST_PORT = True # Remove destination port!
MLP = False
RF = True
CR_VAL_TRAIN = False
DATA_VERSION = "no_artefacts_with_payload_filter"
# 3 random states for each dataset iteration: 42, 43, 44
DATA_SPLIT_RANDOM_STATE = 44
RF_RANDOM_STATE = 44

def gen_id():
    return datetime.utcnow().strftime("%d-%m_%H%-M%-S")


def plot_confusion_matrix(y_true, y_pred, classes,
                          normalize=True,
                          cmap=plt.cm.Reds,
                          save=False,
                          name=None):
    # title =

    # Compute confusion matrix
    cm2 = confusion_matrix(y_true, y_pred)

    if normalize:
        cm = cm2.astype('float') / cm2.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')

    # print(cm)

    fig, ax = plt.subplots(figsize=(9, 9))
    im = ax.imshow(cm, interpolation='nearest', cmap=cmap)
    # ax.figure.colorbar(im, ax=ax)
    # We want to show all ticks...
    ax.set(xticks=np.arange(cm.shape[1]),
           yticks=np.arange(cm.shape[0]),
           # ... and label them with the respective list entries
           # xticklabels=classes, yticklabels=classes,
           # title=title,
           # ylabel='True label',
           # xlabel='Predicted label'
           )
    hfont = {"fontname": "serif"}
    fontsize = "x-large"
    # ax.set_xlabel('Predicted', fontsize=fontsize,**hfont),
    # ax.set_ylabel('True', fontsize=fontsize,**hfont),
    ax.set_xticklabels(classes, fontsize=fontsize, **hfont)
    ax.set_yticklabels(classes, fontsize=fontsize, **hfont, fontweight='bold')

    # Rotate the tick labels and set their alignment.
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
             rotation_mode="anchor")

    # Loop over data dimensions and create text annotations.
    fmt = '.2f' if normalize else 'd'
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm2[i, j], 'd'),  # format(cm[i, j], fmt)
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black")
    fig.tight_layout()

    if save:
        fig.savefig("Figures/" + name + ".pdf", dpi=400,
                    bbox_inches='tight', pad_inches=0)

    plt.show()
    return ax


# https://stackoverflow.com/questions/35249760/using-scikit-to-determine-contributions-of-each-feature-to-a-specific-class-pred
def class_feature_importance(X, Y, feature_importances):
    N, M = X.shape
    X = scale(X)

    out = {}
    for c in set(Y):
        out[c] = dict(
            zip(range(N), np.mean(X[Y == c, :], axis=0) * feature_importances)
        )

    return out


def load_data():
    print("Loading training data ...")
    full_dataset = np.load("NumpyFriendlyData/full_dataset_" + DATA_VERSION + ".npy")

    full_dataset = full_dataset[~np.isnan(full_dataset).any(axis=1)]
    full_dataset = full_dataset[~np.isinf(full_dataset).any(axis=1)]

    data_x = full_dataset[:, :-1]
    data_y = full_dataset[:, -1]

    print(np.unique(data_y, return_counts=True))

    if DITCH_DEST_PORT:
        data_x = data_x[:, 1:]  # Dest Port index = 0

    splits = train_test_split(data_x, data_y, test_size=0.25, stratify=data_y,
                                                        random_state=DATA_SPLIT_RANDOM_STATE)
    return splits


if __name__ == "__main__":

    time_id = gen_id()

    (X_train, X_test, Y_train, Y_test) = load_data()
    print(X_train.shape, X_test.shape)

    # from sklearn.tree import DecisionTreeClassifier
    # print("Decision Tree")
    # clf = DecisionTreeClassifier(criterion='entropy', random_state=0)

    if MLP:
        #X_train = minmax_scale(X_train)
        #X_test = minmax_scale(X_test)

        print("Applying minmax-scaling on train and test set")
        scaler = MinMaxScaler()
        scaler.fit(X_train)
        X_train = scaler.transform(X_train)
        X_test = scaler.transform(X_test)

        print("Multilayered Perceptron")
        mlp_classifier = MLPClassifier(hidden_layer_sizes=(156,78,39))

        print("wrong script for MLP")
        exit(0)

    scoring = {
        'accuracy': make_scorer(accuracy_score),
        'precision': make_scorer(precision_score, average='weighted'),
        'f1_score': make_scorer(f1_score, average='weighted'),
        'recall': make_scorer(recall_score, average='weighted')
    }

    print("Random Forest")
    rf_classifier = RandomForestClassifier(n_estimators=50, max_depth=20, random_state=RF_RANDOM_STATE)

    if CR_VAL_TRAIN:
        print("Cross validating ...")
        sc = cross_validate(rf_classifier, X_train, Y_train, cv=5, scoring=scoring)
        print("Score:\n", sc)

        # print("Fit time:   " % (sc['fit_time']))
        # print("Score time: " % (sc['score_time']))

        print("Precision: %0.8f (%0.8f)" % (sc['test_precision'].mean(), sc['test_precision'].std()))
        print("Recall: %0.8f (%0.8f)" % (sc['test_recall'].mean(), sc['test_recall'].std()))
        print("F1_score: %0.8f (%0.8f)" % (sc['test_f1_score'].mean(), sc['test_f1_score'].std()))
        print("Accuracy: %0.8f (%0.8f)" % (sc['test_accuracy'].mean(), sc['test_accuracy'].std()))

    print("Fitting model ...")
    rf_classifier.fit(X_train, Y_train)

    Y_pred = rf_classifier.predict(X_test)

    nY_test = []
    nY_pred = []
    for i in range(len(Y_test)):
        nY_test += [Y_test[i]]
        nY_pred += [Y_pred[i]]
    Y_test = np.array(nY_test)
    Y_pred = np.array(nY_pred)
    print(Y_test.shape, Y_pred.shape)

    # %%

    classes = ["Benign", "FTP-Patator", "SSH-Patator", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris",
               "Heartbleed", "Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - Sql Injection", "Infiltration",
               "Bot", "PortScan", "DDoS"]

    plot_confusion_matrix(Y_test, Y_pred, classes, save=True, name="RF_" + DATA_VERSION + "_" + time_id )

    prfs = precision_recall_fscore_support(Y_test, Y_pred, average='weighted')
    print("Precision, Recall, F-Score, Support:", prfs)

    # %%

    plot_confusion_matrix(Y_test, Y_pred, classes)

    prfs = precision_recall_fscore_support(Y_test, Y_pred, average='weighted')
    print("Precision, Recall, F-Score, Support:", prfs)
    with open("Scores/RF_" + DATA_VERSION + "_" + time_id  + "_metrics_aggregated.txt", 'w') as out_file:
        out_file.write("Precision, Recall, F-Score, Support: " + str(prfs))

    Y_pred = list(Y_pred)

    np.save("Class-based_metrics/Y_test_" + DATA_VERSION + "_" + time_id, Y_test)
    np.save("Class-based_metrics/Y_pred_" + DATA_VERSION + "_" + time_id, Y_pred)

    class_based_metrics = classification_report(Y_test, Y_pred, target_names=classes, zero_division="warn", digits=4)
    print("Class based metrics:\r\n", class_based_metrics)
    with open("Scores/RF_" + DATA_VERSION + "_metrics_class_based_" + time_id + ".txt", 'w') as out_file:
        out_file.write(class_based_metrics)

    # This next part is to calculate the feature importance for a RF classifier. Comment this out if you're using MLP

    feature_importances = rf_classifier.feature_importances_

    result = class_feature_importance(X_test, Y_pred, feature_importances)

    print(json.dumps(result, indent=4))

    with open("FeatureImportance/feature_importance_full_dataset_" + DATA_VERSION + "_" + time_id + ".json", 'w') as f:
        json.dump(result, f)

'''
features_list = "Dst Port,Protocol,Flow Duration,Total Fwd Packet," \
                "Total Bwd packets,Total Length of Fwd Packet,Total Length of Bwd Packet,Fwd Packet Length Max," \
                "Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,Bwd Packet Length Max," \
                "Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,Flow Bytes/s,Flow Packets/s," \
                "Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std," \
                "Fwd IAT Max,Fwd IAT Min,Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min," \
                "Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd Header Length,Bwd Header Length," \
                "Fwd Packets/s,Bwd Packets/s,Packet Length Min,Packet Length Max,Packet Length Mean,Packet Length Std," \
                "Packet Length Variance,FIN Flag Count,SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count," \
                "URG Flag Count,CWR Flag Count,ECE Flag Count,Down/Up Ratio,Average Packet Size,Fwd Segment Size Avg," \
                "Bwd Segment Size Avg,Fwd Bytes/Bulk Avg,Fwd Packet/Bulk Avg,Fwd Bulk Rate Avg,Bwd Bytes/Bulk Avg," \
                "Bwd Packet/Bulk Avg,Bwd Bulk Rate Avg,Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets," \
                "Subflow Bwd Bytes,FWD Init Win Bytes,Bwd Init Win Bytes,Fwd Act Data Pkts,Fwd Seg Size Min," \
                "Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,Label".split(',')

label_dictionary = {
    'BENIGN': '0',
    'FTP-Patator': '1',
    'SSH-Patator': '2',
    'DoS GoldenEye': '3',
    'DoS Hulk': '4',
    'DoS Slowhttptest': '5',
    'DoS slowloris': '6',
    'Heartbleed': '7',
    'Web Attack – Brute Force': '8',
    'Web Attack – XSS': '9',
    'Web Attack – Sql Injection': '10',
    'Infiltration': '11',
    'Bot': '12',
    'PortScan': '13',
    'DDoS': '14'
}
'''
