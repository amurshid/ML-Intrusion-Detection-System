import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, ConfusionMatrixDisplay
import pickle 
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from preprocessing_data import prepare_data 


def train_and_save_model():
    # Load the prepared data and scaler
    print("Loading and preparing data from network_data.csv...")
    X_scaled, y, scaler = prepare_data('network_data.csv')
    print(f"Data prepared. Total samples remaining after cleaning: {X_scaled.shape[0]}")
    
    # Split data into training and testing sets (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Initialize and Train the Decision Tree Model
    print("Starting model training...")
    model = DecisionTreeClassifier(random_state=42) 
    model.fit(X_train, y_train)
    print("Model training complete.")

    # Evaluate and Plot the Confusion Matrix
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy on Test Set: {accuracy * 100:.2f}%")
    
    # Create and save the Confusion Matrix plot
    cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Normal (0)', 'Malicious (1)'])
    fig, ax = plt.subplots(figsize=(6, 6))
    disp.plot(ax=ax, cmap=plt.cm.Blues)
    ax.set_title('Confusion Matrix for IDS')
    plt.savefig('confusion_matrix.png')
    plt.close()

    # Visualize Feature Separation (ICMP Ratio vs. ARP Ratio)
    df = pd.read_csv('network_data.csv')
    feature_cols = ['ARP_Count', 'ICMP_Count', 'TCP_Count', 'UDP_Count', 'Other_Count']
    malicious_filter = (df['Label'] == 1) & (df[feature_cols].sum(axis=1) > 0)
    normal_filter = df['Label'] == 0
    df_cleaned = df[malicious_filter | normal_filter].copy()
    
    # Add ratio features to the cleaned DataFrame
    df_cleaned['ICMP_Ratio'] = df_cleaned['ICMP_Count'] / (df_cleaned['UDP_Count'] + 1)
    df_cleaned['ARP_Ratio'] = df_cleaned['ARP_Count'] / (df_cleaned['UDP_Count'] + 1)

    # Plot the two most informative features
    plt.figure(figsize=(8, 6))
    sns.scatterplot(
        x=df_cleaned['ICMP_Ratio'], 
        y=df_cleaned['ARP_Ratio'], 
        hue=df_cleaned['Label'], 
        palette={0: 'green', 1: 'red'}, 
        style=df_cleaned['Label'],
        markers={0: 'o', 1: 'X'}
    )
    plt.title('Data Distribution: ICMP Ratio vs. ARP Ratio')
    plt.xlabel('ICMP Ratio (Spikes for Ping Flood)')
    plt.ylabel('ARP Ratio (Spikes for ARP Spoofing)')
    plt.legend(title='Traffic Type', labels=['Normal', 'Malicious'])
    plt.grid(True)
    plt.savefig('feature_distribution.png')
    plt.close()


    # Save the trained model and the scaler object
    with open('intrusion_detector_model.pkl', 'wb') as file:
        pickle.dump(model, file)
        
    with open('min_max_scaler.pkl', 'wb') as file:
        pickle.dump(scaler, file)
        
    print("Model saved as intrusion_detector_model.pkl")
    print("Scaler saved as min_max_scaler.pkl")

if __name__ == '__main__':
    train_and_save_model()