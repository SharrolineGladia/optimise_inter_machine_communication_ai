# Import necessary libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from datetime import datetime

# Step 1: Load and prepare the data
def load_data(file_path):
    """Load network traffic data from CSV file"""
    df = pd.read_csv(file_path)
    
    # Convert timestamp to datetime
    base_date = "2025-04-17 "  # Using today's date
    df['Timestamp'] = pd.to_datetime(base_date + df['Timestamp'])
    
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
        plt.plot(df['Timestamp'], df[metric])
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

# Step 2: Prepare data for Isolation Forest
def prepare_data_for_isolation_forest(df):
    """Extract numeric features and prepare for Isolation Forest"""
    # Select only numeric columns for the model
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    # Remove timestamp as a feature if it was converted to numeric
    if 'Timestamp' in numeric_cols:
        numeric_cols.remove('Timestamp')
    
    # Create feature matrix
    X = df[numeric_cols].copy()
    
    # Handle missing values if any
    X.fillna(X.median(), inplace=True)
    
    # Scale the features for better model performance
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    return X, X_scaled, numeric_cols

# Step 3: Build and apply Isolation Forest
def detect_anomalies_with_isolation_forest(X_scaled, df, contamination=0.05, random_state=42):
    """Build Isolation Forest model and detect anomalies"""
    # Initialize and fit the Isolation Forest model
    model = IsolationForest(contamination=contamination, random_state=random_state)
    model.fit(X_scaled)
    
    # Predict anomalies (-1 for anomalies, 1 for normal)
    df['anomaly'] = model.predict(X_scaled)
    
    # Convert to binary (True for anomalies, False for normal)
    df['anomaly'] = df['anomaly'] == -1
    
    # Get anomaly scores (lower = more anomalous)
    df['anomaly_score'] = model.decision_function(X_scaled)
    
    # Print summary of anomalies
    anomaly_count = df['anomaly'].sum()
    print(f"\nDetected {anomaly_count} anomalies ({anomaly_count/len(df)*100:.2f}% of data)")
    
    return df, model

# Step 4: Visualize and analyze anomalies
def visualize_anomalies(df, numeric_cols):
    """Visualize the detected anomalies across different metrics"""
    # Plot time series with anomalies highlighted
    metrics = ['Latency(ms)', 'Packet Loss(%)', 'Data Rate(Mbps)', 'CPU Usage(%)', 'Memory Usage(%)']
    
    for metric in metrics:
        if metric in numeric_cols:
            plt.figure(figsize=(12, 6))
            
            # Plot normal points
            plt.scatter(df[~df['anomaly']]['Timestamp'], df[~df['anomaly']][metric], 
                      label='Normal', alpha=0.6, color='blue', s=40)
            
            # Plot anomalies
            plt.scatter(df[df['anomaly']]['Timestamp'], df[df['anomaly']][metric], 
                      label='Anomaly', alpha=0.9, color='red', s=80)
            
            plt.title(f'Anomalies in {metric}')
            plt.xlabel('Timestamp')
            plt.ylabel(metric)
            plt.legend()
            plt.tight_layout()
            plt.savefig(f'anomalies_{metric.replace("(%)", "").replace("(", "").replace(")", "")}.png')
            plt.close()
    
    # Visualize anomalies using PCA for dimensionality reduction
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(StandardScaler().fit_transform(df[numeric_cols]))
    
    plt.figure(figsize=(10, 8))
    plt.scatter(X_pca[~df['anomaly'], 0], X_pca[~df['anomaly'], 1], label='Normal', alpha=0.6, s=40)
    plt.scatter(X_pca[df['anomaly'], 0], X_pca[df['anomaly'], 1], label='Anomaly', color='red', alpha=0.9, s=80)
    plt.title('PCA Visualization of Anomalies')
    plt.xlabel('Principal Component 1')
    plt.ylabel('Principal Component 2')
    plt.legend()
    plt.tight_layout()
    plt.savefig('pca_anomalies.png')
    plt.close()
    
    # Plot anomaly score distribution
    plt.figure(figsize=(10, 6))
    plt.hist(df['anomaly_score'], bins=50, alpha=0.7)
    plt.axvline(x=0, color='red', linestyle='--', alpha=0.7)
    plt.title('Distribution of Anomaly Scores')
    plt.xlabel('Anomaly Score (lower = more anomalous)')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.savefig('anomaly_score_distribution.png')
    plt.close()
    
    return

# Step 5: Analyze scenario distribution of anomalies
def analyze_anomalies_by_scenario(df):
    """Analyze the distribution of anomalies across different scenarios"""
    if 'Scenario' in df.columns:
        # Create contingency table of anomalies by scenario
        anomaly_by_scenario = pd.crosstab(df['Scenario'], df['anomaly'], 
                                         rownames=['Scenario'], 
                                         colnames=['Is Anomaly'], 
                                         normalize='index') * 100
        
        # Display percentage of anomalies in each scenario
        print("\nAnomaly Distribution by Scenario (%):")
        print(anomaly_by_scenario)
        
        # Plot anomaly distribution by scenario
        plt.figure(figsize=(10, 6))
        anomaly_by_scenario[True].sort_values(ascending=False).plot(kind='bar')
        plt.title('Percentage of Anomalies by Scenario')
        plt.xlabel('Scenario')
        plt.ylabel('Anomaly Percentage (%)')
        plt.tight_layout()
        plt.savefig('anomaly_percentage_by_scenario.png')
        plt.close()
        
        # Create detailed metrics by scenario for anomalies
        metrics = ['Latency(ms)', 'Packet Loss(%)', 'Data Rate(Mbps)', 'CPU Usage(%)', 'Memory Usage(%)']
        
        print("\nMetric Statistics for Anomalies by Scenario:")
        anomaly_df = df[df['anomaly']]
        
        for scenario in df['Scenario'].unique():
            scenario_anomalies = anomaly_df[anomaly_df['Scenario'] == scenario]
            if len(scenario_anomalies) > 0:
                print(f"\nScenario: {scenario} (Total Anomalies: {len(scenario_anomalies)})")
                print(scenario_anomalies[metrics].describe().round(2))
    
    return

# Step 6: Feature importance analysis
def analyze_feature_importance(model, numeric_cols):
    """Analyze which features contribute most to anomaly detection"""
    # This is a simplified approach to understanding feature importance in Isolation Forest
    # since Isolation Forest doesn't provide direct feature importance scores
    
    # Compute feature importance from the decision path
    n_samples = 1000
    max_features = len(numeric_cols)
    
    # Generate random data following the same structure
    random_data = np.random.randn(n_samples, max_features)
    
    # Get decision paths
    paths = model.estimators_[0].decision_path(random_data).toarray()
    
    # Count how many times each feature is used in the forest
    feature_counts = np.zeros(max_features)
    
    for estimator in model.estimators_:
        paths = estimator.decision_path(random_data).toarray()
        leaves = estimator.apply(random_data)
        
        for leaf in np.unique(leaves):
            path_indices = np.where(leaves == leaf)[0]
            if len(path_indices) > 0:
                # Get path for each sample in this leaf
                sample_path = paths[path_indices[0], :]
                # Count features used in this path
                for i in range(sample_path.shape[0]):
                    if sample_path[i] > 0:  # If this node is in the path
                        node = estimator.tree_.children_left[i]  # Get node split info
                        if node != -1:  # Not a leaf
                            feature = estimator.tree_.feature[i]
                            if feature != -2:  # Not a dummy split
                                feature_counts[feature] += 1
    
    # Normalize counts
    feature_importance = feature_counts / np.sum(feature_counts)
    
    # Plot feature importance
    plt.figure(figsize=(10, 6))
    sorted_idx = np.argsort(feature_importance)
    plt.barh(range(len(sorted_idx)), feature_importance[sorted_idx])
    plt.yticks(range(len(sorted_idx)), [numeric_cols[i] for i in sorted_idx])
    plt.title('Feature Importance in Isolation Forest')
    plt.xlabel('Relative Importance')
    plt.tight_layout()
    plt.savefig('feature_importance.png')
    plt.close()
    
    # Print feature importance
    print("\nFeature Importance:")
    for i, idx in enumerate(reversed(sorted_idx)):
        print(f"{numeric_cols[idx]}: {feature_importance[idx]:.4f}")
    
    return feature_importance, numeric_cols

# Main function to run the anomaly detection
def main(file_path='datasets/combined_dataset_2025-04-17_14-16-59.csv', contamination=0.05):
    """Main function to run the anomaly detection pipeline"""
    print("Starting Network Traffic Anomaly Detection with Isolation Forest...")
    
    # Load and explore data
    df = load_data(file_path)
    explore_data(df)
    
    # Prepare data for Isolation Forest
    X, X_scaled, numeric_cols = prepare_data_for_isolation_forest(df)
    
    # Apply Isolation Forest for anomaly detection
    df_with_anomalies, model = detect_anomalies_with_isolation_forest(X_scaled, df, contamination=contamination)
    
    # Visualize anomalies
    visualize_anomalies(df_with_anomalies, numeric_cols)
    
    # Analyze anomalies by scenario
    analyze_anomalies_by_scenario(df_with_anomalies)
    
    # Analyze feature importance
    analyze_feature_importance(model, numeric_cols)
    
    # Save results
    df_with_anomalies.to_csv('anomaly_detection_results.csv', index=False)
    
    print("\nAnomaly detection completed. Results saved to 'anomaly_detection_results.csv'")
    
    # Show top anomalies
    top_anomalies = df_with_anomalies[df_with_anomalies['anomaly']].sort_values('anomaly_score')
    
    if len(top_anomalies) > 0:
        print("\nTop 10 Most Anomalous Data Points:")
        print(top_anomalies[['Timestamp', 'Scenario', 'Latency(ms)', 'Packet Loss(%)', 
                         'Data Rate(Mbps)', 'CPU Usage(%)', 'Memory Usage(%)', 
                         'anomaly_score']].head(10))
    else:
        print("\nNo anomalies detected with the current configuration.")

if __name__ == "__main__":
    # Adjust the contamination parameter to control sensitivity (lower = fewer anomalies)
    main(file_path='datasets/combined_dataset_2025-04-17_14-16-59.csv', contamination=0.05)