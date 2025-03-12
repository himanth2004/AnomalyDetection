import numpy as np
import joblib
import pandas as pd
from sklearn.svm import LinearSVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score

data = pd.read_csv('datasetforproject_UPDATED.csv')
features = ['L4_SRC_PORT', 'TCP_FLAGS', 'L4_DST_PORT', 'PROTOCOL', 'L7_PROTO']
target = 'Label'

X = data[features]
y = data[target]



X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

svm = LinearSVC(C=0.00001, max_iter=1000, penalty='l2', dual=False, tol=1e-1, intercept_scaling=0.1)
svm.fit(X_train, y_train)

y_pred = svm.predict(X_test)

joblib.dump({'model': svm, 'scaler': scaler}, 'model.joblib')
