# Machine Learning Models for Detecting DDoS and Data Integrity Attacks in M2M Networks



## 📌 Project Execution Summary



### 1. Data Collection & Simulation

- Simulated inter-machine (M2M) network traffic, capturing both normal and attack traffic scenarios.
- Captured real-time packet data using Wireshark and generated attack traffic using Scapy, including DDoS floods and data integrity violations.
- Created two primary datasets:
  - Wireshark Traffic Data CSV (raw captured packet metadata)
  - Combined Attack Data CSV (merged benign, DDoS, and data integrity attack records)



### 2. Label Generation with Heuristic Rules

- Applied a domain-driven heuristic approach to label each packet as Malicious, Suspicious, or Normal.
- Defined labeling rules based on:
  - Presence of 'malformed' keyword in the Info field.
  - Packet size greater than 1000 bytes.
  - TCP packets with SYN flag without corresponding ACK.
- Converted generated labels into encoded categorical variables for supervised machine learning workflows.



### 3. Data Preprocessing

- Handled missing values using median/mode imputation and safely removed records with critical null fields.
- Applied Label Encoding for protocol and flag fields, and One-Hot Encoding for non-ordinal categorical variables.
- Scaled continuous features using StandardScaler to standardize feature magnitudes.
- Split data into 70% training and 30% testing subsets, applying stratified sampling to maintain original class distribution.
- Addressed class imbalance using SMOTE oversampling and random under-sampling where appropriate.



### 4. Machine Learning Model Development

- Trained and evaluated multiple machine learning classifiers including:
  - Random Forest
  - XGBoost
  - LightGBM
  - Multi-Layer Perceptron (MLP)
  - Support Vector Machine (SVM)
  - K-Nearest Neighbors (KNN)
  - Logistic Regression
  - Gradient Boosting



### 5. Model Performance Comparison

| Model               | Accuracy | Precision | Recall | F1 Score |
|:-------------------|:----------|:-----------|:---------|:-----------|
| Random Forest        | 0.9889    | 0.9883     | 0.9883    | 0.9883     |
| XGBoost              | 0.9722    | 0.9702     | 0.9727    | 0.9710     |
| LightGBM             | 0.9889    | 0.9883     | 0.9883    | 0.9883     |
| Gradient Boosting    | 0.9778    | 0.9761     | 0.9779    | 0.9768     |
| MLP                  | 0.8944    | 0.9050     | 0.8818    | 0.8855     |
| SVM                  | 0.8889    | 0.9010     | 0.8754    | 0.8789     |
| KNN                  | 0.9611    | 0.9599     | 0.9587    | 0.9593     |
| Logistic Regression  | 0.7722    | 0.7616     | 0.7612    | 0.7613     |



### 6. Real-Time M2M Suitability Assessment

- Evaluated each model’s feasibility for real-time, edge-based M2M deployment based on:
  - Detection accuracy
  - Inference latency
  - CPU and memory footprint
  - Security resilience against attack types
- Identified Random Forest, LightGBM, and XGBoost as the most reliable models for secure, high-speed, real-time M2M anomaly detection.



### 7. Security and Attack Resilience Analysis

- Assessed resistance of each model to DDoS floods, evasion tactics, data poisoning, and manipulation attacks.
- Observations:
  - XGBoost offered the best overall defense with high resilience and deployment scalability.
  - Random Forest demonstrated strong performance, ease of interpretability, and real-time suitability.
  - LightGBM achieved high accuracy and low inference time, ideal for edge deployments.
  - MLP was accurate but prone to overfitting on class-imbalanced data.
  - SVM performed well in offline or small-scale scenarios but inefficient for large-scale live networks.
  - KNN showed high latency and poor scalability in real-time.
  - Logistic Regression was extremely fast but lacked complex attack protection capabilities.



### 8. Final Deliverables

- Deployed an AI-based multi-class anomaly detection system for real-time classification of:
  - Benign traffic
  - DDoS attacks
  - Data Integrity attacks
- Integrated real-time monitoring dashboards using Prometheus and Grafana for live anomaly visualization.
- Proposed a scalable, hybrid deployment architecture combining:
  - Heuristic-driven edge filtering
  - AI-driven ML classification at cloud infrastructure




