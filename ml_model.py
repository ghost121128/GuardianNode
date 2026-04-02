import numpy as np
from sklearn.ensemble import IsolationForest

X_train = np.array([
    [100, 1], [120, 1], [130, 2], [90, 1], [110, 2]
])

model = IsolationForest(contamination=0.2)
model.fit(X_train)

def predict(packet_size, connections):
    data = np.array([[packet_size, connections]])
    return "ANOMALY" if model.predict(data)[0] == -1 else "NORMAL"