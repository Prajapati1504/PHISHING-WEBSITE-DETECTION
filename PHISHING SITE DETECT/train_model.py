import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from feature_extraction import extract_features

# Load dataset
data = pd.read_csv("data/Tsites.csv")

# Extract features from URL column (FIXED)
X = data['URL'].apply(extract_features).tolist()
y = data['label']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Train model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)
model.fit(X_train, y_train)

# Evaluate
print("Accuracy:", accuracy_score(y_test, model.predict(X_test)))

# Save model
joblib.dump(model, "rf_phishing_model.pkl")
