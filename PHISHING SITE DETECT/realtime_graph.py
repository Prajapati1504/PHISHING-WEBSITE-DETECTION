import pandas as pd
import matplotlib.pyplot as plt

data = pd.read_csv("runtime_results.csv")

counts = data["Prediction"].value_counts()

plt.figure()
counts.plot(kind="bar")
plt.title("Real-Time Prediction Distribution")
plt.ylabel("Count")
plt.xlabel("Prediction")
plt.tight_layout()
plt.show()
