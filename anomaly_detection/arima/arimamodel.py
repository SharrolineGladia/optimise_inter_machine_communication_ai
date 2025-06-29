# Import necessary libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from statsmodels.tsa.arima.model import ARIMA
from statsmodels.tsa.stattools import adfuller
from statsmodels.graphics.tsaplots import plot_acf, plot_pacf
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

# Step 2: Check stationarity and prepare for ARIMA modeling
def check_stationarity(series):
    """Test time series stationarity using Augmented Dickey-Fuller test"""
    result = adfuller(series.dropna())
    print(f"ADF Statistic: {result[0]}")
    print(f"p-value: {result[1]}")
    print("Critical Values:")
    for key, value in result[4].items():
        print(f"\t{key}: {value}")
    
    # Interpret p-value
    if result[1] <= 0.05:
        print("Series is stationary (reject H0)")
    else:
        print("Series is non-stationary (fail to reject H0)")
        
    return result[1] <= 0.05  # Returns True if stationary

def differentiate_if_needed(series):
    """Apply differencing if the series is not stationary"""
    is_stationary = check_stationarity(series)
    diff_order = 0
    
    if not is_stationary:
        diff_series = series.diff().dropna()
        diff_order = 1
        is_stationary = check_stationarity(diff_series)
        
        if not is_stationary:
            diff_series = diff_series.diff().dropna()
            diff_order = 2
            check_stationarity(diff_series)
    
    return diff_order

def determine_arima_orders(series, diff_order):
    """Determine p, d, q parameters for ARIMA model using ACF and PACF plots"""
    # d is already determined by differencing
    d = diff_order
    
    # Apply differencing if needed for ACF/PACF analysis
    if d > 0:
        series = series.diff(d).dropna()
    
    # Plot ACF and PACF to determine p and q
    plt.figure(figsize=(12, 6))
    
    plt.subplot(121)
    plot_acf(series, ax=plt.gca(), lags=20)
    plt.title('Autocorrelation Function')
    
    plt.subplot(122)
    plot_pacf(series, ax=plt.gca(), lags=20)
    plt.title('Partial Autocorrelation Function')
    
    plt.tight_layout()
    plt.savefig('acf_pacf_plots.png')
    plt.close()
    
    p = 1  # AR order
    q = 1  # MA order
    
    print(f"Suggested ARIMA orders: p={p}, d={d}, q={q}")
    return p, d, q

# Step 3: Build and evaluate ARIMA model
def build_arima_model(series, p, d, q):
    """Build ARIMA model with specified orders"""
    model = ARIMA(series, order=(p, d, q))
    model_fit = model.fit()
    
    print("\nARIMA Model Summary:")
    print(model_fit.summary())
    
    return model_fit

def detect_anomalies(series, model_fit, threshold=2.5):
    """Detect anomalies using the fitted ARIMA model and threshold"""
    # Get predictions
    predictions = model_fit.predict(start=series.index[0], end=series.index[-1])
    
    # Calculate residuals (actual - predicted)
    residuals = pd.Series(series.values - predictions.values, index=series.index)
    
    # Calculate mean and standard deviation of residuals
    mean_residual = residuals.mean()
    std_residual = residuals.std()
    
    # Define threshold for anomalies (Z-score approach)
    threshold_upper = mean_residual + threshold * std_residual
    threshold_lower = mean_residual - threshold * std_residual
    
    # Identify anomalies
    anomalies = pd.Series(False, index=series.index)
    anomalies[residuals > threshold_upper] = True
    anomalies[residuals < threshold_lower] = True
    
    # Plot the series, predictions, and anomalies
    plt.figure(figsize=(12, 6))
    plt.plot(series.index, series.values, label='Actual')
    plt.plot(predictions.index, predictions.values, label='Predicted', color='red')
    plt.scatter(series.index[anomalies], series[anomalies], color='green', label='Anomalies', s=100, marker='o')
    plt.fill_between(series.index, 
                     predictions + threshold * std_residual,
                     predictions - threshold * std_residual,
                     color='lightgray', alpha=0.3, label='Threshold Range')
    plt.title(f'Anomaly Detection using ARIMA Model (threshold = {threshold})')
    plt.legend()
    plt.tight_layout()
    plt.savefig('anomaly_detection.png')
    plt.close()
    
    # Return the anomalies and their values
    anomaly_results = pd.DataFrame({
        'value': series[anomalies],
        'predicted': predictions[anomalies],
        'residual': residuals[anomalies],
        'z_score': (residuals[anomalies] - mean_residual) / std_residual
    })
    
    return anomaly_results

# Step 4: Apply anomaly detection to all relevant metrics
def detect_all_anomalies(df, threshold=2.5):
    """Apply anomaly detection to multiple metrics"""
    metrics = ['Latency(ms)', 'Packet Loss(%)', 'Data Rate(Mbps)', 'CPU Usage(%)', 'Memory Usage(%)']
    all_anomalies = {}
    
    for metric in metrics:
        print(f"\n===== Analyzing {metric} =====")
        series = df[metric]
        
        # Check stationarity and determine differencing order
        diff_order = differentiate_if_needed(series)
        
        # Determine ARIMA orders
        p, d, q = determine_arima_orders(series, diff_order)
        
        # Build ARIMA model
        try:
            model_fit = build_arima_model(series, p, d, q)
            
            # Detect anomalies
            anomalies = detect_anomalies(series, model_fit, threshold)
            if not anomalies.empty:
                all_anomalies[metric] = anomalies
                print(f"Found {len(anomalies)} anomalies in {metric}")
            else:
                print(f"No anomalies detected in {metric}")
        except Exception as e:
            print(f"Error building ARIMA model for {metric}: {e}")
    
    return all_anomalies

# Main function to run the anomaly detection
def main(file_path='datasets\combined_dataset_2025-04-17_14-16-59.csv', threshold=2.5):
    """Main function to run the anomaly detection pipeline"""
    print("Starting Network Traffic Anomaly Detection...")
    
    # Load and explore data
    df = load_data(file_path)
    explore_data(df)
    
    # Detect anomalies across all metrics
    all_anomalies = detect_all_anomalies(df, threshold)
    
    # Print summary of anomalies
    print("\n===== Anomaly Detection Summary =====")
    if not all_anomalies:
        print("No anomalies detected in any metric.")
    else:
        for metric, anomalies in all_anomalies.items():
            print(f"\nAnomalies in {metric}:")
            print(anomalies)
    
    print("\nAnomaly detection completed.")
    
    # Additional analysis - Compare metrics across scenarios
    if 'Scenario' in df.columns:
        print("\n===== Scenario Analysis =====")
        scenarios = df['Scenario'].unique()
        metrics = ['Latency(ms)', 'Packet Loss(%)', 'Data Rate(Mbps)', 'CPU Usage(%)', 'Memory Usage(%)']
        
        for metric in metrics:
            plt.figure(figsize=(12, 6))
            for scenario in scenarios:
                scenario_data = df[df['Scenario'] == scenario]
                plt.plot(scenario_data.index, scenario_data[metric], label=scenario)
            
            plt.title(f'{metric} by Scenario')
            plt.legend()
            plt.tight_layout()
            plt.savefig(f'{metric}_by_scenario.png')
            plt.close()

if __name__ == "__main__":
    # If you have a CSV file, pass the path here
    main(file_path='datasets\combined_dataset_2025-04-17_14-16-59.csv')