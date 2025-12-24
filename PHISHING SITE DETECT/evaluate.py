import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# -------- Accuracy Bar Chart --------
methods = ['ML (Clean)', 'ML (Adversarial)', 'Hybrid ML + Rules']
accuracy = [92.7, 78.4, 89.6]

plt.figure()
plt.bar(methods, accuracy)
plt.ylabel('Accuracy (%)')
plt.title('Accuracy Comparison Under Different Scenarios')
plt.show()

# -------- Confusion Matrix --------
cm = np.array([[88, 12],
               [9, 91]])

plt.figure()
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Phishing', 'Legitimate'],
            yticklabels=['Phishing', 'Legitimate'])
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix – Hybrid Model')
plt.show()
