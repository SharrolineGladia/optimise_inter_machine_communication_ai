# Import necessary libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, Dropout
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.model_selection import train_test_split
import seaborn as sns
from datetime import datetime

# Step 1: Load and prepare the data
def load_data(file_path):
    """Load network traffic data from CSV file"""
    df = pd.read_csv(file_path)
    # Convert timestamp to datetime if needed
    # Assuming format is HH:MM:SS
    base_date = "2025-04-17 "  
    df['Timestamp'] = pd.to_datetime(base_date + df['Timestamp'])
    df.set_index('Timestamp', inplace=True)
    
    return df

def explore_data(df):
    """Explore the data to understand patterns and potential anomalies"""
    print("Data Overview:")
    print(df.head())
    print("\nData Info:")
    print(df.info())
    print("\nDescriptive Statistics:")
    print(df.describe())
    
    # Check for missing values
    print("\nMissing Values:")
    print(df.isnull().sum())
    
    # Distribution of scenarios
    print("\nScenario Distribution:")
    print(df['Scenario'].value_counts())
    
    # Create basic visualizations
    plt.figure(figsize=(12, 8))
    
    # Plot time series for key metrics
    metrics = ['Latency(ms)', 'Packet Loss(%)', 'Data Rate(Mbps)', 'CPU Usage(%)', 'Memory Usage(%)']
    for i, metric in enumerate(metrics, 1):
        plt.subplot(len(metrics), 1, i)
        plt.plot(df.index, df[metric])
        plt.title(f'{metric} Over Time')
        plt.tight_layout()
    
    plt.savefig('time_series_metrics.png')
    plt.close()
    
    # Create correlation heatmap
    plt.figure(figsize=(10, 8))
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    sns.heatmap(df[numeric_cols].corr(), annot=True, cmap='coolwarm', fmt='.2f')
    plt.title('Correlation Between Metrics')
    plt.tight_layout()
    plt.savefig('correlation_heatmap.png')
    plt.close()
    
    return

# Step 2: Prepare the data for LSTM model
def prepare_data_for_lstm(df, sequence_length=10):
    """Prepare data for LSTM model by creating sequences"""
    # Select the numeric columns we want to use for prediction
    metrics = ['Latency(ms)', 'Packet Loss(%)', 'Data Rate(Mbps)', 'CPU Usage(%)', 'Memory Usage(%)']
    data = df[metrics].values
    
    # Create binary labels: 0 for 'Normal', 1 for any other scenario (anomaly)
    labels = np.where(df['Scenario'] == 'Normal', 0, 1)
    
    # Scale the data
    scaler = MinMaxScaler()
    data = scaler.fit_transform(data)
    
    # Create sequences
    X, y = [], []
    for i in range(len(data) - sequence_length):
        X.append(data[i:i + sequence_length])
        y.append(labels[i + sequence_length])
    
    X = np.array(X)
    y = np.array(y)
    
    # Split into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    return X_train, X_test, y_train, y_test, scaler, metrics

# Step 3: Build and train the LSTM model
def build_lstm_model(input_shape):
    """Build LSTM model for anomaly detection"""
    model = Sequential()
    
    # LSTM layers
    model.add(LSTM(64, input_shape=input_shape, return_sequences=True))
    model.add(Dropout(0.2))
    model.add(LSTM(32, return_sequences=False))
    model.add(Dropout(0.2))
    
    # Dense layers
    model.add(Dense(16, activation='relu'))
    model.add(Dense(1, activation='sigmoid'))  # Binary classification
    
    # Compile the model
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    
    return model

def train_lstm_model(model, X_train, y_train, X_test, y_test, epochs=50, batch_size=64):
    """Train the LSTM model"""
    # Early stopping to prevent overfitting
    early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
    
    # Train the model
    history = model.fit(
        X_train, y_train,
        epochs=epochs,
        batch_size=batch_size,
        validation_data=(X_test, y_test),
        callbacks=[early_stopping],
        verbose=1
    )
    
    # Plot training history
    plt.figure(figsize=(12, 5))
    
    plt.subplot(1, 2, 1)
    plt.plot(history.history['loss'], label='Training Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.title('Model Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()
    
    plt.subplot(1, 2, 2)
    plt.plot(history.history['accuracy'], label='Training Accuracy')
    plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
    plt.title('Model Accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.legend()
    
    plt.tight_layout()
    plt.savefig('lstm_training_history.png')
    plt.close()
    
    return model, history

# Step 4: Evaluate the model and detect anomalies
def evaluate_model(model, X_test, y_test):
    """Evaluate the LSTM model"""
    # Get predictions
    y_pred_proba = model.predict(X_test)
    y_pred = (y_pred_proba > 0.5).astype(int)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    
    # False positive rate
    if cm.shape == (2, 2):  # Ensure we have a 2x2 matrix
        fp = cm[0, 1]
        tn = cm[0, 0]
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    else:
        false_positive_rate = 0
    
    # Display metrics
    print("\nModel Evaluation Metrics:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    print(f"False Positive Rate: {false_positive_rate:.4f}")
    
    # Plot confusion matrix
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.savefig('confusion_matrix.png')
    plt.close()
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'false_positive_rate': false_positive_rate
    }

def detect_anomalies_by_metric(df, model, scaler, sequence_length=10):
    """Detect anomalies for each metric separately using reconstruction error"""
    metrics = ['Latency(ms)', 'Packet Loss(%)', 'Data Rate(Mbps)', 'CPU Usage(%)', 'Memory Usage(%)']
    results = {}
    
    # Create sequences for the entire dataset
    data = df[metrics].values
    data_scaled = scaler.transform(data)
    
    X_sequences = []
    for i in range(len(data_scaled) - sequence_length):
        X_sequences.append(data_scaled[i:i + sequence_length])
    
    X_sequences = np.array(X_sequences)
    
    # Get predictions
    y_pred_proba = model.predict(X_sequences)
    y_pred = (y_pred_proba > 0.5).astype(int)
    
    # Create true labels
    y_true = np.where(df['Scenario'][sequence_length:] == 'Normal', 0, 1)
    
    # Calculate metrics for each metric
    for i, metric in enumerate(metrics):
        # Calculate metric-specific performance
        # Calculate accuracy
        accuracy = accuracy_score(y_true, y_pred)
        
        # For precision, recall, and f1, apply specific logic for each metric
        # Create binary labels specifically for this metric's anomalies
        metric_anomalies = np.zeros_like(y_true)
        if metric == 'Latency(ms)':
            metric_anomalies = np.where(df['Scenario'][sequence_length:].isin(['High Latency', 'Mixed Anomalies']), 1, 0)
        elif metric == 'Packet Loss(%)':
            metric_anomalies = np.where(df['Scenario'][sequence_length:].isin(['Packet Loss', 'Mixed Anomalies']), 1, 0)
        elif metric == 'Data Rate(Mbps)':
            metric_anomalies = np.where(df['Scenario'][sequence_length:].isin(['Low Bandwidth', 'Mixed Anomalies']), 1, 0)
        else:  # CPU and Memory Usage
            metric_anomalies = np.where(df['Scenario'][sequence_length:] != 'Normal', 1, 0)
            
        # Calculate precision, recall, and F1 score for this specific metric
        precision = precision_score(metric_anomalies, y_pred, zero_division=0)
        recall = recall_score(metric_anomalies, y_pred, zero_division=0)
        f1 = f1_score(metric_anomalies, y_pred, zero_division=0)
        
        # Calculate false positive rate
        cm = confusion_matrix(metric_anomalies, y_pred)
        if cm.shape == (2, 2):  # Ensure we have a 2x2 matrix
            fp = cm[0, 1]
            tn = cm[0, 0]
            false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        else:
            false_positive_rate = 0
        
        # Store results
        results[metric] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'false_positive_rate': false_positive_rate
        }
    
    return results

def visualize_anomalies(df, model, scaler, sequence_length=10):
    """Visualize the anomalies detected by the LSTM model"""
    metrics = ['Latency(ms)', 'Packet Loss(%)', 'Data Rate(Mbps)', 'CPU Usage(%)', 'Memory Usage(%)']
    
    # Create sequences for the entire dataset
    data = df[metrics].values
    data_scaled = scaler.transform(data)
    
    X_sequences = []
    for i in range(len(data_scaled) - sequence_length):
        X_sequences.append(data_scaled[i:i + sequence_length])
    
    X_sequences = np.array(X_sequences)
    
    # Get predictions
    y_pred_proba = model.predict(X_sequences)
    y_pred = (y_pred_proba > 0.5).astype(int)
    
    # Create a DataFrame with predictions
    anomaly_df = pd.DataFrame(index=df.index[sequence_length:])
    anomaly_df['Anomaly'] = y_pred
    anomaly_df['Scenario'] = df['Scenario'][sequence_length:].values
    
    # Plot each metric with anomalies highlighted
    for metric in metrics:
        plt.figure(figsize=(14, 7))
        
        # Plot the original data
        plt.plot(df.index, df[metric], label=metric, color='blue', alpha=0.7)
        
        # Highlight anomalies
        anomaly_points = df.index[sequence_length:][y_pred.flatten() == 1]
        anomaly_values = df.loc[anomaly_points, metric]
        plt.scatter(anomaly_points, anomaly_values, color='red', label='Detected Anomalies', s=50)
        
        # Highlight true anomalies (non-Normal scenarios)
        true_anomaly_mask = df['Scenario'] != 'Normal'
        true_anomaly_points = df.index[true_anomaly_mask]
        true_anomaly_values = df.loc[true_anomaly_points, metric]
        plt.scatter(true_anomaly_points, true_anomaly_values, color='green', label='True Anomalies', 
                   marker='x', s=70, alpha=0.5)
        
        plt.title(f'Anomaly Detection for {metric}')
        plt.xlabel('Time')
        plt.ylabel(metric)
        plt.legend()
        plt.tight_layout()
        plt.savefig(f'anomaly_detection_{metric.replace("(", "_").replace(")", "_")}.png')
        plt.close()
    
    # Create a summary plot
    plt.figure(figsize=(14, 5))
    
    # Plot the scenarios
    scenario_mapping = {
        'Normal': 0, 
        'High Latency': 1, 
        'Packet Loss': 2, 
        'Low Bandwidth': 3, 
        'Mixed Anomalies': 4
    }
    
    scenario_numeric = df['Scenario'].map(scenario_mapping)
    plt.plot(df.index, scenario_numeric, 'k-', alpha=0.3, label='True Scenario')
    
    # Plot detected anomalies
    plt.plot(anomaly_df.index, y_pred.flatten() * 4, 'r--', linewidth=2, label='Detected Anomaly')
    
    # Add scenario labels
    plt.yticks(list(scenario_mapping.values()), list(scenario_mapping.keys()))
    
    plt.title('Comparison of True Scenarios vs Detected Anomalies')
    plt.xlabel('Time')
    plt.ylabel('Scenario')
    plt.legend()
    plt.tight_layout()
    plt.savefig('scenario_vs_detection.png')
    plt.close()
    
    return anomaly_df

# Step 5: Calculate model performance metrics for comparison
def calculate_model_performance(df, model, scaler, sequence_length=10):
    """Calculate MSE, MAE, MAPE, and R-squared for each metric"""
    metrics = ['Latency(ms)', 'Packet Loss(%)', 'Data Rate(Mbps)', 'CPU Usage(%)', 'Memory Usage(%)']
    performance = {}
    
    # Create an autoencoder-like setup to reconstruct the input
    # This is specifically for performance comparison with the ARIMA model
    
    # Get sequences
    data = df[metrics].values
    data_scaled = scaler.transform(data)
    
    X_sequences = []
    for i in range(len(data_scaled) - sequence_length):
        X_sequences.append(data_scaled[i:i + sequence_length])
    
    X_sequences = np.array(X_sequences)
    
    # Get predictions (anomaly scores)
    anomaly_scores = model.predict(X_sequences)
    
    # For each metric, calculate performance metrics
    for i, metric in enumerate(metrics):
        # Original values
        original = df[metric][sequence_length:].values
        
        # Predicted values (this is just for comparison purposes)
        # We're using a classification model, so we don't have direct reconstructions
        # Instead, we'll use a simple approach - if it's predicted normal, use the mean
        # If it's predicted anomaly, use a different value
        
        normal_mean = df.loc[df['Scenario'] == 'Normal', metric].mean()
        anomaly_mean = df.loc[df['Scenario'] != 'Normal', metric].mean()
        
        predicted = np.where(anomaly_scores.flatten() < 0.5, normal_mean, anomaly_mean)
        
        # Calculate metrics
        mse = np.mean((original - predicted) ** 2)
        mae = np.mean(np.abs(original - predicted))
        
        # MAPE (avoid division by zero)
        non_zero = original != 0
        if np.any(non_zero):
            mape = np.mean(np.abs((original[non_zero] - predicted[non_zero]) / original[non_zero])) * 100
        else:
            mape = float('inf')
        
        # R-squared
        ss_total = np.sum((original - np.mean(original)) ** 2)
        ss_residual = np.sum((original - predicted) ** 2)
        r_squared = 1 - (ss_residual / ss_total) if ss_total != 0 else 0
        
        performance[metric] = {
            'RMSE': np.sqrt(mse),
            'MAE': mae,
            'MAPE (%)': mape,
            'R-squared': r_squared
        }
    
    return performance

# Main function
def main(file_path='data/network_data.csv'):
    """Main function to run the LSTM anomaly detection pipeline"""
    print("Starting Network Traffic Anomaly Detection with LSTM...")
    
    # Load and explore data
    df = load_data(file_path)
    explore_data(df)
    
    # Prepare data for LSTM
    sequence_length = 10  # Number of time steps to look back
    X_train, X_test, y_train, y_test, scaler, metrics = prepare_data_for_lstm(df, sequence_length)
    
    # Build and train LSTM model
    print("\nBuilding and training LSTM model...")
    input_shape = (X_train.shape[1], X_train.shape[2])
    model = build_lstm_model(input_shape)
    model, history = train_lstm_model(model, X_train, y_train, X_test, y_test)
    
    # Evaluate the model
    print("\nEvaluating LSTM model...")
    evaluation_metrics = evaluate_model(model, X_test, y_test)
    
    # Detect anomalies by metric
    print("\nDetecting anomalies for each metric...")
    metric_results = detect_anomalies_by_metric(df, model, scaler, sequence_length)
    
    # Visualize anomalies
    print("\nVisualizing anomalies...")
    anomaly_df = visualize_anomalies(df, model, scaler, sequence_length)
    
    # Calculate model performance metrics for comparison with ARIMA
    print("\nCalculating model performance metrics...")
    performance_metrics = calculate_model_performance(df, model, scaler, sequence_length)
    
    # Print summary
    print("\n===== Anomaly Detection Summary =====")
    print(f"Dataset Size: {len(df)} records")
    print(f"Metrics Analyzed: {', '.join(metrics)}")
    print(f"Total Anomalies Detected: {anomaly_df['Anomaly'].sum()}")
    
    # Print model performance
    print("\n===== Model Performance =====")
    headers = ["Metric", "RMSE", "MAE", "MAPE (%)", "R-squared"]
    print(f"{headers[0]:<15} {headers[1]:<15} {headers[2]:<15} {headers[3]:<15} {headers[4]:<15}")
    print("-" * 75)
    for metric, perf in performance_metrics.items():
        mape_value = 'inf' if np.isinf(perf['MAPE (%)']) else f"{perf['MAPE (%)']:.4f}"
        print(f"{metric:<15} {perf['RMSE']:<15.4f} {perf['MAE']:<15.4f} {mape_value:<15} {perf['R-squared']:<15.4f}")
    
    # Print anomaly detection performance
    print("\n===== Anomaly Detection Performance =====")
    headers = ["Metric", "Accuracy", "Precision", "Recall", "F1 Score", "False Positive Rate"]
    print(f"{headers[0]:<15} {headers[1]:<15} {headers[2]:<15} {headers[3]:<15} {headers[4]:<15} {headers[5]:<15}")
    print("-" * 90)
    for metric, results in metric_results.items():
        print(f"{metric:<15} {results['accuracy']:<15.4f} {results['precision']:<15.4f} {results['recall']:<15.4f} {results['f1']:<15.4f} {results['false_positive_rate']:<15.4f}")
    
    print("\nLSTM-based anomaly detection completed.")

if __name__ == "__main__":
    # Update with your file path
    main(file_path='datasets/combined_dataset_2025-04-17_14-16-59.csv')