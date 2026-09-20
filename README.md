# Phishing URL Detector

An AI-powered tool that classifies URLs as phishing or legitimate using a
Random Forest model trained on URL-structure and page-behavior features.

## Overview

This project started as a follow-up to a rule-based password strength
analyser — instead of hand-written rules, this version uses a trained
machine learning model to make the classification decision.

## Dataset

- Source: [https://www.kaggle.com/vishalsiram50/phishing-websigtes-data] (11,055 labeled URLs)
- 30 pre-engineered features covering URL structure, domain/certificate
  info, page content signals, and traffic/reputation data
- Balanced classes: 6,157 legitimate, 4,898 phishing

## Approach

1. Explored and understood the feature set (see `explore.ipynb`)
2. Trained a Logistic Regression baseline
3. Trained and tuned a Random Forest model
4. Compared results and selected the best-performing model
5. Built a CLI tool (`detector.py`) that extracts a practical subset of
   features from a raw URL and runs them through the trained model

## Results

| Model | Accuracy | Phishing Recall | Missed Phishing (False Negatives) |
|---|---|---|---|
| Logistic Regression | 92.45% | 0.90 | 91 |
| Random Forest (tuned) | 97% | 0.95 | 45 |

Random Forest cut missed phishing detections roughly in half compared to
the baseline.

**Top predictive features:** `SSLfinal_State` and `URL_of_Anchor` account
for over half the model's decision-making, consistent with known phishing
patterns (invalid/missing SSL certificates, anchor links pointing to
unrelated domains).

## Known Limitation

The trained model uses 30 features, but several (SSL certificate state,
live page anchor links, web traffic, page rank) require external lookups
that aren't practical to compute instantly for a CLI demo. The live tool
(`detector.py`) currently computes 7 URL-structure features and defaults
the rest to neutral, which noticeably lowers confidence on borderline
cases (e.g. shortened URLs, IP-based URLs). Extending this with live SSL
certificate checks and WHOIS domain age lookups is a planned next step.

## How to Run

\`\`\`
python -m venv venv
venv\\Scripts\\activate      # Windows
pip install -r requirements.txt
python detector.py
\`\`\`

## Project Structure

\`\`\`
phishing-detector/
├── data/
│   └── phishing.csv
├── explore.ipynb          # data exploration + model training
├── detector.py            # CLI tool for real-time URL checking
├── phishing_model.pkl     # trained model
├── requirements.txt
└── README.md
\`\`\`