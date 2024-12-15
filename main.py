import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix
from scipy.io import arff
from sklearn.metrics import accuracy_score
from xgboost import XGBRegressor
from sklearn.feature_selection import RFE

arffFile = arff.loadarff('KDDTrain+.arff')
df = pd.DataFrame(arffFile[0])

#print(df.isnull().sum())
#print(df.head())

label_encoder = LabelEncoder()
categorical_columns = df.select_dtypes(include=['object', 'category']).columns

# Apply LabelEncoder to each categorical column
for col in categorical_columns:
    df[col] = label_encoder.fit_transform(df[col])

#print(df.head())
X = df.drop(columns=['class'])
y = df['class']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=42)

model = XGBRegressor(random_state=42)

rfe = RFE(estimator=model, n_features_to_select=10, step=1)
rfe.fit(X_train, y_train)

print("Selected Features:", X.columns[rfe.support_])
print("Feature Ranking:", rfe.ranking_)

# # # Test performance
# y_pred = rfe.predict(X_test)
# print("Accuracy:", accuracy_score(y_test, y_pred))

# print(df.info())