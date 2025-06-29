# Anomaly Detection

This module focuses on detecting anomalies in inter-machine communication using real-time telemetry data collected under various network conditions.

## Directory Structure

- `datasets/`  
  Contains:
  - `server.py` and `client.py` scripts to simulate machine-to-machine communication.
  - Raw datasets generated under different network conditions.
  
  > **Important:** Before running each scenario, configure **Clumsy** with the appropriate settings (see table below) to simulate desired network behavior.

- `combine_scenarios.py`  
  Merges scenario-specific datasets into a unified dataset for training and evaluation.

- `arima/`, `isolation_forest_lstm/`  
  These folders contain:
  - Model-specific code for training and inference.
  - `outputs/` directory for storing result plots and logs.

---

## Scenario Simulation using Clumsy

Before generating datasets, use **Clumsy** to simulate network anomalies. The table below outlines recommended configurations for each test scenario:

| Scenario         | Configuration                                                                                  | Purpose                                                                 |
|------------------|-----------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| **Normal**       | `Lag: 30ms`                                                                                    | Simulates ideal conditions with slight lag to mimic realistic localhost communication. |
| **High Latency** | `Lag: 200–500ms`                                                                               | Adds artificial delay to packets, simulating long-distance or overloaded networks. |
| **Packet Loss**  | `Drop rate: 20% or higher`                                                                     | Randomly drops packets to mimic unstable or poor connections.          |
| **Low Bandwidth**| `Throttle: 50–500ms`                                                                           | Simulates slow or congested networks by limiting throughput.           |
| **Mixed Anomalies** | `Lag: 150–300ms`<br>`Drop: 10–30%`<br>`Throttle: 100–300 KBps`                              | Combines multiple faults for realistic degradation scenarios.          |

Each configuration helps generate scenario-specific data that reflects distinct communication issues, improving model robustness.

---

## Workflow

1. Run the server and client in `datasets/` under each Clumsy scenario.
2. Collect and save the output CSVs.
3. Use `combine_scenarios.py` to merge all scenario datasets into one.
4. Navigate to a model folder (`arima/`, `isolation_forest_lstm/`) to train and test anomaly detection models.
5. Review results and visualizations in the respective `outputs/` directories.

---

This module supports identifying performance anomalies caused by degraded network conditions and contributes to the broader system’s intelligent decision-making capability.
