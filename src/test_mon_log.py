import pickle, numpy as np

with open('../models/random_forest.pkl', 'rb') as f:
	model = pickle.load(f)

with open('../models/scaler.pkl', 'rb') as f:
	scaler = piscle.load(f)

log_suspect = [3,5,1,1,0,4,30,25,1,3,1,0,1,3,1,0,0,0,0,]
X = scaler.transform([log_suspect])
proba = model.predict_proba(X)[0][1]
print(f'Score : {proba:.3f}')
