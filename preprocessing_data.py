import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
import numpy as np

def prepare_data(filename='network_data.csv'):
    # Load the data
    df = pd.read_csv(filename)

    # Filter inconsistent Malicious samples
    # Keep samples where Label=1 ONLY if at least one protocol count is > 0
    # Sum across the rows for the feature columns
    feature_cols = ['ARP_Count', 'ICMP_Count', 'TCP_Count', 'UDP_Count', 'Other_Count']
    malicious_filter = (df['Label'] == 1) & (df[feature_cols].sum(axis=1) > 0)
    normal_filter = df['Label'] == 0
    
    df_cleaned = df[malicious_filter | normal_filter]

    # Separate features (X) and target (y)
    X = df_cleaned.drop('Label', axis=1)
    y = df_cleaned['Label']

    X['ICMP_Ratio'] = X['ICMP_Count'] / (X['UDP_Count'] + 1)
    X['ARP_Ratio'] = X['ARP_Count'] / (X['UDP_Count'] + 1)

    # Scale the features (Normalization)
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    
    y_array = y.to_numpy() 

    return X_scaled, y_array, scaler