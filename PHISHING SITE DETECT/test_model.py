
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score
from feature_extraction import extract_features
from adversarial_attacks import generate_adversarial_urls

model = joblib.load('rf_phishing_model.pkl')
data = pd.read_csv('data/Tsites.csv')

X = data['url'].apply(extract_features).tolist()
y = data['label']

print("Baseline Accuracy:", accuracy_score(y, model.predict(X)))

adv_urls = []
for u in data['url']:
    adv_urls.extend(generate_adversarial_urls(u).values())

X_adv = [extract_features(u) for u in adv_urls]
print("Adversarial Accuracy:", accuracy_score([1]*len(X_adv), model.predict(X_adv)))
