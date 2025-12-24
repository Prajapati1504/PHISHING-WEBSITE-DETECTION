import pandas as pd
import joblib

# Load model
model = joblib.load("rf_phishing_model.pkl")

# Load data
data = pd.read_csv("data/Tsites.csv")

# Keep numeric columns only
data = data.select_dtypes(include=['number'])

# Separate features
X = data.drop('label', axis=1)

# Predict
predictions = model.predict(X)

# Convert to Series and map
predictions = pd.Series(predictions)
data['Prediction'] = predictions.map({
    0: 'Legitimate Website',
    1: 'Phishing Website'
})

print(data[['Prediction']].head(10))
