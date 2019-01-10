import os
import sys
sys.path.insert(0, os.path.abspath('../'))
import json, io,  base64
import pandas as pd
import numpy as np
import math
import pickle 
import sklearn
import imblearn
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import RFE
import itertools
from collections import defaultdict
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import RandomOverSampler 
from collections import Counter
from sklearn.preprocessing import OneHotEncoder
import Intrusion_data_cleaning
from sklearn import metrics


from flask import Flask, render_template, request


app = Flask(__name__)

def get_model():
	global model 
	model = pickle.load(open("intrusion_knn.pkl","rb"))
	print("Model loaded")
	
get_model()

"""
website host
 
"""

@app.route('/')
def index():
	"""
	/ Initial interface: Rest API
      
	:returns: html to select the html file
	"""
	return '<form ENCTYPE="multipart/form-data" action = "/result" method = "POST"><input name="file" type="file" accept=".txt"/><input name="submit" type="submit"/></form>'


	  
@app.route('/result',methods = ['POST'])
def result():
	"""
	/result methods = ['POST']: Rest API to submit the 10K HTM/HTML file 

	:returns: render_template for template/result.html
	"""
	if request.method == 'POST':
		file = request.files["file"]
		actual_value,predicted_value = Intrusion_data_cleaning.clean_file(file)
		Prediction = model.predict(predicted_value)
		
		output = metrics.classification_report(actual_value, Prediction)
		return render_template("int_out.html", result= Prediction, output = output )






if __name__ == '__main__':
	"""
	Start the App
	"""
	app.run(debug = True)