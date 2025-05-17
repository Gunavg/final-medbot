import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from pymongo import MongoClient
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

def preprocess_dataset(dataset_df):
    """Create a binary symptom matrix from dataset."""
    symptom_cols = [col for col in dataset_df.columns if col.startswith('Symptom_')]
    symptoms = set()
    for col in symptom_cols:
        symptoms.update(dataset_df[col].dropna().unique())
    symptoms = sorted(list(symptoms))
    
    symptom_matrix = pd.DataFrame(0, index=dataset_df.index, columns=symptoms)
    for idx, row in dataset_df.iterrows():
        for col in symptom_cols:
            symptom = row[col]
            if pd.notna(symptom) and symptom in symptoms:
                symptom_matrix.loc[idx, symptom] = 1
    
    symptom_matrix['Disease'] = dataset_df['Disease']
    return symptom_matrix, symptoms

def correlation_matrix(symptom_matrix, symptoms):
    """Generate and display a neat correlation matrix heatmap for symptom pairings."""
    # Limit to top 20 symptoms to reduce congestion
    symptom_counts = symptom_matrix[symptoms].sum()
    top_symptoms = symptom_counts.nlargest(20).index.tolist()
    corr_matrix = symptom_matrix[top_symptoms].corr()
    
    title = 'Correlation Matrix of Top Symptoms'
    print(f"\nDisplaying: {title}")
    
    plt.figure(figsize=(16, 14))
    sns.heatmap(
        corr_matrix,
        annot=False,
        cmap='viridis',
        center=0,
        vmin=-1,
        vmax=1,
        square=True,
        cbar_kws={'label': 'Correlation Coefficient', 'shrink': 0.8}
    )
    plt.title(title, fontsize=20, pad=25, weight='bold')
    plt.xlabel('Symptoms', fontsize=14)
    plt.ylabel('Symptoms', fontsize=14)
    plt.xticks(rotation=60, ha='right', fontsize=8)
    plt.yticks(fontsize=8)
    plt.grid(True, which='minor', linestyle='--', alpha=0.2)
    plt.tight_layout()
    plt.show()
    
    # Print high-correlation pairs
    high_corr = corr_matrix.where((corr_matrix > 0.3) & (corr_matrix != 1)).stack()
    print("\nFrequent Symptom Pairings (Correlation > 0.3):")
    print("-" * 50)
    print(f"{'Symptom Pair':<35} {'Correlation':>12}")
    print("-" * 50)
    for (sym1, sym2), corr in high_corr.items():
        pair = f"{sym1} and {sym2}"
        print(f"{pair:<35} {corr:>12.2f}")

def pairplots(symptom_matrix, symptoms):
    """Generate and display a smaller, neat pairplot for top symptoms by disease."""
    symptom_counts = symptom_matrix[symptoms].sum()
    top_symptoms = symptom_counts.nlargest(4).index.tolist()
    key_symptoms = ['fatigue', 'weight_loss', 'nausea', 'vomiting']
    top_symptoms = list(set(top_symptoms + [s for s in key_symptoms if s in symptoms]))[:4]
    
    pairplot_data = symptom_matrix[top_symptoms + ['Disease']]
    
    title = 'Pairplot of Top Symptoms by Disease'
    print(f"\nDisplaying: {title}")
    
    sns.set_style("whitegrid")
    pair_plot = sns.pairplot(
        pairplot_data,
        hue='Disease',
        vars=top_symptoms,
        diag_kind='kde',
        palette='deep',
        markers='o',
        height=2.5,  # Reduced size
        aspect=1.2,  # Slightly wider subplots
        plot_kws={'s': 80, 'alpha': 0.7},  # Smaller points
        diag_kws={'alpha': 0.5}
    )
    pair_plot.figure.suptitle(title, y=1.05, fontsize=18, weight='bold')
    pair_plot._legend.set_title('Disease', prop={'size': 12, 'weight': 'bold'})
    for text in pair_plot._legend.texts:
        text.set_fontsize(10)
    pair_plot._legend.set_bbox_to_anchor((1.05, 0.5))
    for ax in pair_plot.axes.flatten():
        ax.set_xlabel(ax.get_xlabel(), fontsize=11)
        ax.set_ylabel(ax.get_ylabel(), fontsize=11)
        ax.tick_params(labelsize=9)
    plt.tight_layout()
    plt.show()

def grouped_bar_plots(dataset_df, symptom_matrix):
    """Generate and display a neat bar plot of symptom counts by disease category."""
    complex_diseases = ['Diabetes', 'Hepatitis', 'Heart attack', 'Tuberculosis']
    dataset_df['Category'] = dataset_df['Disease'].apply(
        lambda x: 'Complex' if x in complex_diseases else 'Non-Complex'
    )
    
    dataset_df['Symptom_Count'] = symptom_matrix.drop(columns=['Disease']).sum(axis=1)
    
    category_counts = dataset_df.groupby('Category')['Symptom_Count'].mean().reset_index()
    
    title = 'Average Symptom Count by Disease Category'
    print(f"\nDisplaying: {title}")
    
    plt.figure(figsize=(8, 6))
    bar_plot = sns.barplot(
        x='Category',
        y='Symptom_Count',
        hue='Category',
        data=category_counts,
        palette='muted',
        edgecolor='black',
        legend=False
    )
    plt.title(title, fontsize=18, pad=20, weight='bold')
    plt.xlabel('Disease Category', fontsize=12)
    plt.ylabel('Average Symptom Count', fontsize=12)
    plt.xticks(fontsize=10)
    plt.yticks(fontsize=10)
    plt.grid(True, axis='y', linestyle='--', alpha=0.7)
    for p in bar_plot.patches:
        bar_plot.annotate(
            f'{p.get_height():.1f}',
            (p.get_x() + p.get_width() / 2., p.get_height()),
            ha='center', va='bottom', fontsize=10
        )
    plt.tight_layout()
    plt.show()

def scatter_plot_severity(predictions_df):
    """Generate and display a neat scatter plot of symptom severity vs. disease."""
    def calculate_severity(answers, answer_types):
        if not answers or not answer_types:
            return 0
        severity = 0
        for ans, atype in zip(answers, answer_types):
            if atype == 'numeric':
                try:
                    severity += float(ans)
                except (ValueError, TypeError):
                    continue
        return severity
    
    predictions_df['Severity'] = predictions_df.apply(
        lambda row: calculate_severity(
            row.get('follow_up_answers', []),
            row.get('follow_up_answer_types', [])
        ),
        axis=1
    )
    
    def get_disease_class(diseases):
        if not diseases or not isinstance(diseases, list):
            return 'Unknown'
        return diseases[0]['name']
    
    predictions_df['Disease'] = predictions_df['diseases'].apply(get_disease_class)
    
    complex_diseases = ['Diabetes', 'Hepatitis', 'Heart attack', 'Tuberculosis']
    predictions_df['Category'] = predictions_df['Disease'].apply(
        lambda x: 'Complex' if x in complex_diseases else 'Non-Complex'
    )
    
    title = 'Total Symptom Severity vs. Disease'
    print(f"\nDisplaying: {title}")
    
    plt.figure(figsize=(10, 8))
    sns.scatterplot(
        x='Severity',
        y='Disease',
        hue='Category',
        size='Severity',
        sizes=(50, 200),
        data=predictions_df,
        palette='dark',
        alpha=0.7
    )
    plt.title(title, fontsize=18, pad=20, weight='bold')
    plt.xlabel('Total Symptom Severity', fontsize=12)
    plt.ylabel('Disease', fontsize=12)
    plt.xticks(fontsize=10)
    plt.yticks(rotation=0, fontsize=8)
    plt.legend(title='Category', title_fontsize=12, fontsize=10, loc='center left', bbox_to_anchor=(1, 0.5))
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.show()

def main():
    dataset_df, predictions_df = load_data()
    if dataset_df is None or predictions_df is None:
        logger.error("Aborting analysis due to data loading failure.")
        return
    
    symptom_matrix, symptoms = preprocess_dataset(dataset_df)
    
    # Generate and display all plots
    correlation_matrix(symptom_matrix, symptoms)
    pairplots(symptom_matrix, symptoms)
    grouped_bar_plots(dataset_df, symptom_matrix)
    scatter_plot_severity(predictions_df)

if __name__ == '__main__':
    main()