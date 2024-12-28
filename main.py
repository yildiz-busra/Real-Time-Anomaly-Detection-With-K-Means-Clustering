import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.preprocessing import StandardScaler
#from sklearn.metrics import pairwise_distances_argmin_min
import matplotlib.pyplot as plt
#import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix

# veri setini yükle
df = pd.read_csv("input.csv")
#df.drop(columns=["attack_type"])

# 2. veri önişleme
# verisetinde boş değer olup olmadığını kontrol et
#print(df.isnull().sum())
#tcp flag sütununda bulunan boş verileri yenii bir kategori ile doldur
df["tcp_flags"] = df["tcp_flags"].fillna("NOFLAG")
# sns.countplot(x='label', data=df)
# plt.title('Distribution of TCP Flags')
# plt.show()

# 2.1 ketegorik verileri etiketle (label encoding)
label_encoder = LabelEncoder()
categorical_columns = df.select_dtypes(include=["object", "category"]).columns
for col in categorical_columns:
    df[col] = label_encoder.fit_transform(df[col])

# 2.2 normalizasyon
numerical_columns = (
    df.drop(columns=["label"])
    .select_dtypes(include=["int64", "float64"])
    .columns
)
scaler = StandardScaler()
df[numerical_columns] = scaler.fit_transform(df[numerical_columns])

#print(df.tail())

kmeans = KMeans(n_clusters=2, max_iter=1000, random_state=42)  
kmeans.fit(df)


#df['cluster'] = kmeans.labels_
distances = kmeans.transform(df)
distances = np.linalg.norm(distances, axis=1)
threshold = np.percentile(distances, 90)
df['cluster'] = kmeans.predict(df)
df['anomaly'] = distances > threshold
#print(df.iloc[37500:37550])
# print(df.tail())
#true_labels = df['label']
#predicted_labels = df['anomaly'].astype(int)
print("Confusion Matrix:")
print(confusion_matrix(df['label'], df['cluster']))

print("\nClassification Report:")
print(classification_report(df['label'], df['cluster'], target_names=['Normal', 'Anormal']))

plt.scatter(df.index, distances, c=df['cluster'], cmap='coolwarm', alpha=0.7)
plt.axhline(threshold, color='red', linestyle='--')
plt.title('Anomaly Detection in Network Traffic')
plt.xlabel('Data Points')
plt.ylabel('Distance from Cluster Center')
plt.show()
