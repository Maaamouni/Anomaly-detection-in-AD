from elasticsearch import Elasticsearch
import pickle, numpy as np, time

# 1. Connexion à Elasticsearch
es = Elasticsearch("https://localhost:9200",basic_auth=("elastic","changeme"),verify_certs=False)

# 2. Charger le modèle entraîné
model = pickle.load(open("models/random_forest.pkl", "rb"))

# 3. Boucle toutes les 30 secondes
while True:
	# Récupérer les logs de la dernière minute
	# index should be changed
	res = es.search(index="ad-logs-*", query={"range": {"@timestamp": {"gte": "now-1m"}}})
	for hit in res["hits"]["hits"]:
		score = model.predict_proba(scaler.transform([features]))[0][1]
		if score > 0.8: print(f"ALERTE [{score:.2f}]")
	time.sleep(30)
