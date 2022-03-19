import numpy as np
from sklearn.ensemble import RandomForestClassifier as rfc
from sklearn.model_selection import train_test_split
import pickle

# Importing dataset
data = np.loadtxt("src/api/dataset.csv", delimiter = ",")

# Seperating features and labels
X = data[: , :-1]
y = data[: , -1]

# Seperating training features, testing features, training labels & testing labels
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2)
clf = rfc()
clf.fit(X_train, y_train)
score = clf.score(X_test, y_test)
print(score*100)
pickle.dump(clf,open("src/api/dtc.pickle","wb"))