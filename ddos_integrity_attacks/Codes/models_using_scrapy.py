import time
import random
import pandas as pd
import psutil
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import plotly.graph_objects as go
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder, StandardScaler
import lightgbm as lgb

# ---- SIMULATE NETWORK TRAFFIC FOR 3 CLASSES ----
def simulate_traffic(label, duration=10):
    """
    Simulate network traffic data for a given label.
    Generates packets with protocol, packet_size, cpu, memory, label.
    """
    data = []
    start_time = time.time()
    while time.time() - start_time < duration:
        # Simulate packet size & protocol based on label
        if label == "normal":
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            packet_size = random.randint(50, 500)
        elif label == "ddos":
            protocol = "UDP"
            packet_size = random.randint(1000, 1500)
        elif label == "data_integrity":
            protocol = "TCP"
            packet_size = random.randint(40, 1000)
        else:
            protocol = "TCP"
            packet_size = random.randint(50, 500)

        # System stats (simulate or fetch real values)
        cpu = psutil.cpu_percent(interval=0.01)
        memory = psutil.virtual_memory().percent

        # Append one packet row
        data.append({
            "protocol": protocol,
            "packet_size": packet_size,
            "cpu": cpu,
            "memory": memory,
            "label": label
        })

        time.sleep(0.01)  # Small delay to simulate time passage

    return pd.DataFrame(data)

def run_and_save(label, duration=10):
    print(f"Simulating {label} traffic for {duration} seconds...")
    df = simulate_traffic(label, duration)
    filename = f"{label}_traffic.csv"
    df.to_csv(filename, index=False)
    print(f"Saved {label} data to {filename}")
    return df

# ---- SECURITY RADAR VISUALIZATION ----
def plot_security_radar(models, metrics, scores, save_dir="charts"):
    """
    Create an interactive security radar chart for ML models
    
    Parameters:
    models (list): List of model names
    metrics (list): List of security metrics (radar axes)
    scores (2D array): Scores for each model on each metric (shape: models x metrics)
    """
    os.makedirs(save_dir, exist_ok=True)
    fig = go.Figure()

    # Convert scores to numpy array if not already
    scores = np.array(scores)
    
    # Normalize scores to 0-1 range for better visualization
    scores_normalized = (scores - scores.min(axis=0)) / (scores.max(axis=0) - scores.min(axis=0) + 1e-9)
    scores_normalized = scores_normalized * 0.9 + 0.1  # Scale to 0.1-1.0 range
    
    # Create radar traces for each model
    colors = plt.cm.tab10.colors  # Use matplotlib's tab10 colors
    for i, model in enumerate(models):
        fig.add_trace(go.Scatterpolar(
            r=np.append(scores_normalized[i], scores_normalized[i][0]),  # Close the loop
            theta=np.append(metrics, metrics[0]),  # Close the loop
            fill='toself',
            name=model,
            line=dict(color=f'rgb({int(colors[i][0]*255)},{int(colors[i][1]*255)},{int(colors[i][2]*255)}'),
            opacity=0.7
        ))
    
    # Update layout for better visualization
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 1.1],
                tickvals=[0.1, 0.3, 0.5, 0.7, 0.9, 1.0],
                ticktext=['Low', '', 'Medium', '', 'High', 'Max'],
                tickangle=45
            ),
            angularaxis=dict(
                direction="clockwise",
                rotation=90
            )
        ),
        title='ML Model Security & Attack Resilience Radar',
        title_x=0.5,
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.1,
            xanchor="center",
            x=0.5
        ),
        width=800,
        height=600,
        margin=dict(l=50, r=50, b=50, t=80)
    )
    
    # Save as HTML for interactive viewing
    fig.write_html(os.path.join(save_dir, "security_radar_chart.html"))
    print(f"Saved interactive security radar chart to {save_dir}/security_radar_chart.html")
    
    # Also save as static image
    fig.write_image(os.path.join(save_dir, "security_radar_chart.png"))
    print(f"Saved static security radar chart to {save_dir}/security_radar_chart.png")

# ---- TRAIN MODELS ----
def train_models(df, save_dir="models"):
    os.makedirs(save_dir, exist_ok=True)

    # Encode categorical data
    protocol_le = LabelEncoder()
    label_le = LabelEncoder()
    df["protocol_enc"] = protocol_le.fit_transform(df["protocol"])
    df["label_enc"] = label_le.fit_transform(df["label"])

    features = ["cpu", "memory", "packet_size", "protocol_enc"]
    X = df[features]
    y = df["label_enc"]

    # Split dataset (train/test) to prevent overfitting
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save encoders and scaler
    joblib.dump(protocol_le, os.path.join(save_dir, "protocol_label_encoder.pkl"))
    joblib.dump(label_le, os.path.join(save_dir, "label_label_encoder.pkl"))
    joblib.dump(scaler, os.path.join(save_dir, "scaler.pkl"))

    # Define models with some tuning to reduce overfitting
    models = {
        "RandomForest": RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42),
        "XGBoost": XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42, max_depth=6, n_estimators=50),
        "MLP": MLPClassifier(max_iter=300, hidden_layer_sizes=(50,), random_state=42),
        "SVM": SVC(probability=True, kernel='rbf', C=1.0, random_state=42),
        "KNN": KNeighborsClassifier(n_neighbors=5),
        "GradientBoosting": GradientBoostingClassifier(random_state=42, n_estimators=50, max_depth=5),
        "LogisticRegression": LogisticRegression(max_iter=300, random_state=42),
        "LightGBM": lgb.LGBMClassifier(random_state=42, max_depth=6, n_estimators=50),
    }

    print("\nTraining models...")
    for name, model in models.items():
        print(f"Training {name}...")
        model.fit(X_train_scaled, y_train)
        joblib.dump(model, os.path.join(save_dir, f"{name}_model.pkl"))

        # Evaluate on test set
        y_pred = model.predict(X_test_scaled)
        report = classification_report(y_test, y_pred, target_names=label_le.classes_)
        with open(os.path.join(save_dir, f"{name}_report.txt"), "w") as f:
            f.write(report)

        acc = accuracy_score(y_test, y_pred)
        print(f"{name} Test Accuracy: {acc:.4f}")
    print("Training complete.")

# ---- EVALUATE MODELS ----
def evaluate_models(df, models_dir="models", save_dir="charts"):
    os.makedirs(save_dir, exist_ok=True)

    protocol_le = joblib.load(os.path.join(models_dir, "protocol_label_encoder.pkl"))
    label_le = joblib.load(os.path.join(models_dir, "label_label_encoder.pkl"))
    scaler = joblib.load(os.path.join(models_dir, "scaler.pkl"))

    df['protocol_enc'] = protocol_le.transform(df['protocol'])
    df['label_enc'] = label_le.transform(df['label'])

    features = ["cpu", "memory", "packet_size", "protocol_enc"]
    X = df[features]
    y = df["label_enc"]

    # Split test dataset (same split as in training ideally, but here we just use 20% for evaluation)
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_test_scaled = scaler.transform(X_test)

    model_names = ["RandomForest", "XGBoost", "MLP", "SVM", "KNN", "GradientBoosting", "LogisticRegression", "LightGBM"]
    results = []

    for name in model_names:
        model_path = os.path.join(models_dir, f"{name}_model.pkl")
        if not os.path.exists(model_path):
            print(f"Model file not found for {name}, skipping.")
            continue
        model = joblib.load(model_path)
        y_pred = model.predict(X_test_scaled)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
        rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

        results.append({
            "Model": name,
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1 Score": f1
        })

        # Plot confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                    xticklabels=label_le.classes_, yticklabels=label_le.classes_)
        plt.title(f"Confusion Matrix - {name}")
        plt.xlabel("Predicted")
        plt.ylabel("True")
        plt.tight_layout()
        plt.savefig(f"{save_dir}/confusion_matrix_{name}.png")
        plt.close()

    results_df = pd.DataFrame(results)
    print("\nModel performance summary on test data:")
    print(results_df)

    # Plot metrics bar chart
    plt.figure(figsize=(12, 8))
    results_df.set_index("Model")[["Accuracy", "Precision", "Recall", "F1 Score"]].plot(kind="bar")
    plt.title("Model Comparison Metrics on Test Set")
    plt.ylabel("Score")
    plt.ylim(0, 1)
    plt.grid(True)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f"{save_dir}/model_comparison_metrics.png")
    plt.close()

    # Security assessment metrics
    security_metrics = [
        "DDoS Resilience",
        "Data Poisoning Resistance", 
        "Spagging Detection",
        "Overfitting Protection",
        "Feature Manipulation Tolerance",
        "Evasion Robustness"
    ]
    
    # Security scores (these would ideally come from empirical testing)
    # Scores are on a scale of 1-10 (higher is better)
    security_scores = {
        "RandomForest": [8, 7, 6, 7, 6, 7],
        "XGBoost": [9, 8, 7, 8, 7, 8],
        "MLP": [5, 4, 5, 4, 5, 6],
        "SVM": [6, 5, 6, 5, 6, 7],
        "KNN": [4, 3, 4, 3, 4, 5],
        "GradientBoosting": [7, 6, 5, 6, 5, 6],
        "LogisticRegression": [5, 4, 5, 4, 5, 6],
        "LightGBM": [8, 7, 6, 7, 6, 7]
    }
    
    # Convert to arrays for plotting
    scores_array = np.array([security_scores[model] for model in model_names])
    
    # Generate the security radar chart
    plot_security_radar(model_names, security_metrics, scores_array, save_dir)
    
    print(f"\nAll charts and reports saved in '{save_dir}' directory.")

# ---- MAIN ----
if __name__ == "__main__":
    # Step 1: Simulate and save datasets for all classes
    df_normal = run_and_save("normal", duration=10)
    df_ddos = run_and_save("ddos", duration=10)
    df_data_integrity = run_and_save("data_integrity", duration=10)

    # Combine all data
    df_all = pd.concat([df_normal, df_ddos, df_data_integrity], ignore_index=True)
    df_all.to_csv("combined_attack_data.csv", index=False)
    print("\nCombined dataset saved as combined_attack_data.csv")

    # Step 2: Train all models on combined dataset (with train/test split)
    train_models(df_all)

    # Step 3: Evaluate all models and plot charts on test set
    evaluate_models(df_all)