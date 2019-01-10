import os
import sys
sys.path.insert(0, os.path.abspath('../'))
import json, io,  base64
import pandas as pd
import numpy as np
import math
import sklearn
import imblearn
import pickle
pd.set_option('display.max_columns', None)
np.set_printoptions(threshold=np.nan)
np.set_printoptions(precision=3)
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import RFE
import itertools
from collections import defaultdict
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import RandomOverSampler 
from collections import Counter
from sklearn.preprocessing import OneHotEncoder



def clean_file(file):
	datacols = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","attack", "last_flag"]
	
	
	kdd_test = pd.read_table(file, sep=",", names=datacols)
	kdd_test = kdd_test.iloc[:,:-1]
	
	mapping = {'ipsweep': 'Probe','satan': 'Probe','nmap': 'Probe','portsweep': 'Probe','saint': 'Probe','mscan': 'Probe',
        'teardrop': 'DoS','pod': 'DoS','land': 'DoS','back': 'DoS','neptune': 'DoS','smurf': 'DoS','mailbomb': 'DoS',
        'udpstorm': 'DoS','apache2': 'DoS','processtable': 'DoS',
        'perl': 'U2R','loadmodule': 'U2R','rootkit': 'U2R','buffer_overflow': 'U2R','xterm': 'U2R','ps': 'U2R',
        'sqlattack': 'U2R','httptunnel': 'U2R',
        'ftp_write': 'R2L','phf': 'R2L','guess_passwd': 'R2L','warezmaster': 'R2L','warezclient': 'R2L','imap': 'R2L',
        'spy': 'R2L','multihop': 'R2L','named': 'R2L','snmpguess': 'R2L','worm': 'R2L','snmpgetattack': 'R2L',
        'xsnoop': 'R2L','xlock': 'R2L','sendmail': 'R2L',
        'normal': 'Normal'
        }
		
	
	kdd_test['attack_class'] = kdd_test['attack'].apply(lambda v: mapping[v])
	kdd_test.drop(['attack'], axis=1, inplace=True)
	kdd_test.drop(['num_outbound_cmds'], axis=1, inplace=True)
	
	
	scaler = StandardScaler()

	
	cols = kdd_test.select_dtypes(include=['float64','int64']).columns

	sc_test = kdd_test.select_dtypes(include=['float64','int64'])

	
	
	sc_testdf = pd.DataFrame(sc_test, columns = cols)
	
	encoder = LabelEncoder()
	
	
	cattest = kdd_test.select_dtypes(include=['object']).copy()
	testcat = cattest.apply(encoder.fit_transform)
	
	
	enctest = testcat.drop(['attack_class'], axis=1)
	cat_Ytest = testcat[['attack_class']].copy()
	
	
	c, r = cat_Ytest.values.shape
	y_test = cat_Ytest.values.reshape(c,)
	
	
	reftest = pd.concat([sc_testdf, testcat], axis=1)
	reftest['attack_class'] = reftest['attack_class'].astype(np.float64)
	reftest['protocol_type'] = reftest['protocol_type'].astype(np.float64)
	reftest['flag'] = reftest['flag'].astype(np.float64)
	reftest['service'] = reftest['service'].astype(np.float64)
	
	classdict = defaultdict(list)
	
	
	attacklist = [('DoS', 0.0), ('Probe', 2.0), ('R2L', 3.0), ('U2R', 4.0)]
	normalclass = [('Normal', 1.0)]
	
	def create_classdict():
		'''This function subdivides train and test dataset into two-class attack labels''' 
		for j, k in normalclass: 
			for i, v in attacklist: 
				
				reftest_set = reftest.loc[(reftest['attack_class'] == k) | (reftest['attack_class'] == v)]
				classdict[j +'_' + i].append(reftest_set)
        
	create_classdict()

	pretest = classdict['Normal_DoS'][0]
	grpclass = 'Normal_DoS'
	
	enc = OneHotEncoder()

	newtest = pretest
	selected_features = ['src_bytes','dst_bytes','logged_in','count','srv_count','dst_host_srv_count','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_serror_rate','service']
	Xtest_features = newtest[selected_features]
	Xtestdfnum = Xtest_features.drop(['service'], axis=1)
	Xtestcat = Xtest_features[['service']].copy()

	
	
	X_test_1hotenc = Xtestcat

	X_test = np.concatenate((Xtestdfnum.values, X_test_1hotenc), axis=1) 

	y_test = newtest[['attack_class']].copy()
	c, r = y_test.values.shape
	Y_test = y_test.values.reshape(c,)
	
	return Y_test, X_test
	
	
	
	
	