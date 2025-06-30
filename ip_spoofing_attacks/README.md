# IP Spoofing Detection - Inter-Machine Communication Optimizer
![image](https://github.com/user-attachments/assets/9d1f2ca6-6d45-476d-ad3e-429c90d9368b)

## Overview

This module focuses on detecting **IP spoofing attacks** in inter-machine communication systems, a critical threat that allows attackers to impersonate trusted sources by manipulating IP addresses. Detecting such attacks enhances the reliability and security of machine-to-machine (M2M) communication.

## Dataset

- **Dataset Used**: [NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd)
- **Total Records**: ~125,000
- **Features**: 41 (TCP/IP based, content-based, and traffic-based features)
- **Label**: Binary Classification - Normal vs. Attack (focused on DoS/IP Spoofing)

## Preprocessing

- **One-Hot Encoding**: For categorical features like `protocol_type`, `service`, and `flag`.
- **Min-Max Scaling**: For continuous features.
- **Label Simplification**: All attacks were grouped under one label: `Attack`.
- **Train-Test Split**: 80% training and 20% testing (except Logistic Regression: 75-25 split)

## Models Compared

| Model               | Accuracy | Highlights |
|--------------------|----------|------------|
| **XGBoost**         | 99.94%   | Best performer with high precision and recall |
| **Random Forest**   | 99.88%   | Very stable and generalizable |
| **LightGBM**        | 99.91%   | Fastest with almost equal accuracy to XGBoost |
| **Decision Tree**   | 99.78%   | Easy to interpret, slightly prone to overfitting |
| **KNN**             | 99.60%   | Accurate but slow and resource-heavy |
| **SVM**             | 99.21%   | Strong accuracy, not scalable |
| **Logistic Regression** | ~95.2% | Baseline model, struggles with complexity |

## Workflow

1. **Data Loading** and Cleaning  
2. **Encoding** and **Normalization**  
3. **Model Training & Testing**  
4. **Evaluation** via confusion matrix and accuracy  
5. **Model Selection** based on use-case (real-time, offline, etc.)

## Key Takeaways

- XGBoost was found to be the most effective model in detecting IP spoofing with minimal false positives and negatives.
- Random Forest and LightGBM are suitable alternatives depending on resource availability and time constraints.
- Logistic Regression, while fast, is unsuitable for complex spoofing behaviors.

## Conclusion

This IP Spoofing Detection module is part of the broader system to ensure **secure, real-time inter-machine communication**. It uses machine learning to proactively detect malicious activity, enhancing both **security** and **resilience** in distributed systems.

## Future Improvements

- Deploy real-time detection using live traffic instead of offline datasets.
- Integrate with Prometheus + Grafana for real-time alerting on spoofed traffic.
- Implement automatic blocking mechanisms on detection.
