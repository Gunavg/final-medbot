import pandas as pd

# Load original dataset
df = pd.read_csv('E:/NM/Project/project/datasets/dataset.csv')

# Correct typos in Disease names
df['Disease'] = df['Disease'].replace({
    'Peptic ulcer diseae': 'Peptic ulcer disease',
    'Dimorphic hemmorhoids(piles)': 'Hemorrhoids'
})

# Standardize symptom names (remove extra spaces)
for col in [f'Symptom_{i}' for i in range(1, 18)]:
    df[col] = df[col].str.replace('  ', ' ').str.strip()

# Remove duplicates (keep unique disease-symptom combinations)
df_dedup = df.drop_duplicates().reset_index(drop=True)

# Save to new file
df_dedup.to_csv('dataset_corrected.csv', index=False)
print(f"Original rows: {len(df)}, Deduplicated rows: {len(df_dedup)}")