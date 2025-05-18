import pandas as pd
import numpy as np
from pymongo import MongoClient
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import logging

# Set up logging to only show ERROR and above
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# MongoDB setup
mongo_client = MongoClient('mongodb://localhost:27017')
mongo_db = mongo_client['medical_db']
dataset_collection = mongo_db['dataset']
predictions_collection = mongo_db['predictions']

def load_data():
    """Load dataset and predictions from MongoDB."""
    try:
        dataset_df = pd.DataFrame(list(dataset_collection.find()))
        predictions_df = pd.DataFrame(list(predictions_collection.find()))
        for df in [dataset_df, predictions_df]:
            if '_id' in df.columns:
                df.drop(columns=['_id'], inplace=True)
        return dataset_df, predictions_df
    except Exception as e:
        logger.error(f"Error loading data: {e}")
        return None, None

def match_predictions(dataset_df, predictions_df):
    """Match predictions to ground truth based on symptom overlap."""
    # Extract symptoms from dataset
    symptom_cols = [col for col in dataset_df.columns if col.startswith('Symptom_')]
    dataset_symptoms = dataset_df[symptom_cols].apply(
        lambda row: [s for s in row if pd.notna(s)], axis=1
    )
    
    # Extract predicted and actual diseases
    y_true = []
    y_pred = []
    
    for pred_idx, pred_row in predictions_df.iterrows():
        pred_symptoms = set(pred_row.get('symptoms', []))
        if not pred_symptoms:
            continue
        
        # Find matching dataset record with highest symptom overlap
        max_overlap = 0
        best_match_idx = None
        for data_idx, data_symptoms in dataset_symptoms.items():
            overlap = len(set(data_symptoms).intersection(pred_symptoms))
            if overlap > max_overlap:
                max_overlap = overlap
                best_match_idx = data_idx
        
        if best_match_idx is not None and max_overlap > 0:
            actual_disease = dataset_df.loc[best_match_idx, 'Disease']
            predicted_disease = (
                pred_row['diseases'][0]['name']
                if pred_row.get('diseases') and isinstance(pred_row['diseases'], list)
                else 'Unknown'
            )
            y_true.append(actual_disease)
            y_pred.append(predicted_disease)
    
    return y_true, y_pred

def calculate_metrics(y_true, y_pred):
    """Calculate Accuracy, Precision, Recall, and F1-Score."""
    # Overall accuracy
    accuracy = accuracy_score(y_true, y_pred)
    
    # Per-class metrics (macro-average for multi-class)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, average=None, labels=np.unique(y_true), zero_division=0
    )
    
    # Macro-average for overall metrics
    precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true, y_pred, average='macro', zero_division=0
    )
    
    return accuracy, precision, recall, f1, precision_macro, recall_macro, f1_macro, np.unique(y_true)

def print_and_save_metrics(accuracy, precision, recall, f1, precision_macro, recall_macro, f1_macro, classes):
    """Print metrics to console and save to file."""
    output = []
    output.append("\nEvaluation Metrics:")
    output.append("=" * 50)
    output.append(f"{'Metric':<20} {'Value':>10}")
    output.append("-" * 50)
    output.append(f"{'Accuracy':<20} {accuracy:>10.3f}")
    output.append("\nPer-Class Metrics:")
    output.append("-" * 50)
    output.append(f"{'Class':<20} {'Precision':>10} {'Recall':>10} {'F1-Score':>10}")
    output.append("-" * 50)
    
    for cls, prec, rec, f1_score in zip(classes, precision, recall, f1):
        output.append(f"{cls:<20} {prec:>10.3f} {rec:>10.3f} {f1_score:>10.3f}")
    
    output.append("\nMacro-Average Metrics:")
    output.append("-" * 50)
    output.append(f"{'Metric':<20} {'Value':>10}")
    output.append("-" * 50)
    output.append(f"{'Precision':<20} {precision_macro:>10.3f}")
    output.append(f"{'Recall':<20} {recall_macro:>10.3f}")
    output.append(f"{'F1-Score':<20} {f1_macro:>10.3f}")
    output.append("=" * 50)
    
    # Print to console
    for line in output:
        print(line)
    
    # Save to file
    with open('evaluation_metrics.txt', 'w') as f:
        for line in output:
            f.write(line + '\n')

def main():
    # Load data
    dataset_df, predictions_df = load_data()
    if dataset_df is None or predictions_df is None:
        logger.error("Aborting evaluation due to data loading failure.")
        return
    
    # Match predictions to ground truth
    y_true, y_pred = match_predictions(dataset_df, predictions_df)
    if not y_true or not y_pred:
        logger.error("No matching predictions found.")
        return
    
    # Calculate metrics
    accuracy, precision, recall, f1, precision_macro, recall_macro, f1_macro, classes = calculate_metrics(y_true, y_pred)
    
    # Print and save results
    print_and_save_metrics(accuracy, precision, recall, f1, precision_macro, recall_macro, f1_macro, classes)

if __name__ == '__main__':
    main()
    