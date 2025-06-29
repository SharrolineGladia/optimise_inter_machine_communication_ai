# Latency and Throughput Modeling:

**Overview**
This project focuses on analyzing and predicting latency and data throughput across different network types (4G, 5G, LTE) using a time-series dataset. The goal is to identify the most efficient time slots in a 24-hour window using machine learning techniques.

**Dataset:**
🔗 Cellular Network Analysis Dataset on Kaggle

**Dataset Field	Description**
Timestamp-Datetime of the record
Latency (ms)	- Latency in milliseconds
Throughput (Mbps) -	Data throughput in Megabits per second
Network Type	-Type of network (4G, 5G, LTE)

**Data Cleaning**
Removed rows with null or invalid entries -> Converted Timestamp to proper datetime format-> Ensured Latency and Throughput are of numeric data types -> Maintained data consistency and integrity throughout preprocessing.

**Feature Engineering**
1.Temporal Features
Extracted hour and minute from the Timestamp.

Created time blocks (e.g., Morning, Afternoon, Night) for trend analysis.

Split the day into 96 slots (15-min intervals) for fine-grained analysis.

2.Categorical Features
Applied one-hot encoding to the Network Type column (4G, 5G, LTE).

3.Final Feature Set
Combination of: Time-based features (hour, minute, time block)  and Encoded network type features

**Models & Evaluation**
Model	-Latency R² -	Throughput R²	Not
->Gradient Boosting Regressor	0.84	0.74	Best performer; captures complex patterns
->Random Forest Regressor	0.78	0.64	Robust and general-purpose
->K-Nearest Neighbors	0.70	0.63	Simpler model; underperforms comparatively

**Evaluation Metrics**
--Mean Squared Error (MSE) – Lower is better
--R² Score – Higher is better

**Methodology**
1.Split the 24-hour day into 96 time slots (15-minute intervals).
2.Trained Gradient Boosting Regressor to predict: Latency (ms),Throughput (Mbps)
3.Computed an Efficiency Score for each slot:
4.Efficiency Score = Predicted Throughput / Predicted Latency
5.Identified Top 10 high-efficiency time slots and exported them to a .csv file.
6.Generated a heatmap to visualize peak network efficiency.

**Key Findings**
->Gradient Boosting consistently outperforms other models.
->Peak efficiency observed between 1:00 AM – 3:00 AM.
->Night-time slots generally offer better latency-to-throughput ratios.

**Outputs**
1.top_10_slots.csv – Time slots with highest efficiency scores
2.efficiency_heatmap.png – Visual representation of efficiency trends

**Tools & Libraries**
->Python (Pandas, Numpy)
->Scikit-learn (GBR, RFR, KNN)
->Matplotlib & Seaborn (Visualizations)

**Future Enhancements**
*Incorporate real-time network traffic data
*Add geo-location for regional efficiency modeling
*Develop interactive dashboard for slot-based prediction
