import pandas as pd
import glob
import os
import json
from sklearn.preprocessing import LabelEncoder, StandardScaler

def load_and_merge_data(data_dir):
    """Loads all JSON files from the data directory, labels them, and merges them."""
    files = glob.glob(os.path.join(data_dir, '*.json'))
    dfs = []
    
    for f in files:
        filename = os.path.basename(f)
        print(f"Loading {filename}...")
        
        # Determine attack type from filename
        attack_type = filename.replace('.json', '')
        
        # Read JSON (dataset is JSON lines format)
        try:
            df = pd.read_json(f, lines=True)
            df['attack_type'] = attack_type
            # Label as 1 (malicious) by default for these offensive datasets
            df['label'] = 1 
            dfs.append(df)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            
    if not dfs:
        return pd.DataFrame()
        
    # Concatenate all dataframes
    full_df = pd.concat(dfs, axis=0, ignore_index=True, sort=False)
    return full_df

def clean_data(df):
    """Performs data cleaning steps."""
    print("Cleaning data...")
    # Convert timestamp
    df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
    df = df.dropna(subset=['@timestamp'])
    
    # Drop columns with > 90% missing values
    threshold = len(df) * 0.1
    df = df.dropna(thresh=threshold, axis=1)
    
    # Fill remaining NaNs
    cat_columns = df.select_dtypes(include=['object']).columns
    df[cat_columns] = df[cat_columns].fillna('unknown')
    
    num_columns = df.select_dtypes(include=['number']).columns
    df[num_columns] = df[num_columns].fillna(0)
    
    # Remove constant columns
    for col in df.columns:
        if col in ['label', 'attack_type']:
            continue
        try:
            if df[col].nunique() <= 1:
                df = df.drop(col, axis=1)
        except TypeError:
            # Handle columns with lists or other unhashable types
            # We can convert to string or just skip the constant check
            # For now, let's convert to string to see if it's constant
            if df[col].astype(str).nunique() <= 1:
                df = df.drop(col, axis=1)
            
    return df

def extract_features(df):
    """Extracts temporal and behavioral features."""
    print("Extracting features...")
    df = df.sort_values('@timestamp')
    
    # 1. Temporal Features
    df['hour'] = df['@timestamp'].dt.hour
    df['day_of_week'] = df['@timestamp'].dt.dayofweek
    df['is_working_hour'] = df['hour'].apply(lambda x: 1 if 8 <= x <= 18 else 0)
    
    # Time delta between events (global and per-host)
    df['time_delta_sec'] = df['@timestamp'].diff().dt.total_seconds().fillna(0)
    df['host_time_delta_sec'] = df.groupby('Hostname')['@timestamp'].diff().dt.total_seconds().fillna(0)
    
    # 2. Behavioral Features
    # Identify User column (SubjectUserName or TargetUserName or AccountName)
    user_col = 'SubjectUserName' if 'SubjectUserName' in df.columns else 'AccountName'
    
    # Rolling counts of events per user (last 1 minute)
    # Using a simpler trick: group by 1m window
    df['event_count_1m'] = df.groupby([user_col, pd.Grouper(key='@timestamp', freq='1min')])[user_col].transform('count')
    
    # Unique EventID count per Hostname
    df['unique_event_id_per_host'] = df.groupby('Hostname')['EventID'].transform('nunique')
    
    # Is it a sensitive EventID? (e.g., 4624, 4625, 4768, 4769, 4771)
    sensitive_ids = [4624, 4625, 4768, 4769, 4771, 5140, 5145]
    df['is_sensitive_event'] = df['EventID'].isin(sensitive_ids).astype(int)
    
    return df

def encode_and_normalize(df):
    """Encodes categorical variables and normalizes numerical ones."""
    print("Encoding and normalizing...")
    
    # Categorical columns to encode
    cols_to_encode = ['EventID', 'Hostname', 'attack_type', 'SourceName', 'Channel']
    cols_to_encode = [c for c in cols_to_encode if c in df.columns]
    
    le = LabelEncoder()
    for col in cols_to_encode:
        df[col] = le.fit_transform(df[col].astype(str))
        
    # Select numerical features for scaling
    features_to_scale = ['hour', 'day_of_week', 'time_delta_sec', 'host_time_delta_sec', 
                         'event_count_1m', 'unique_event_id_per_host']
    features_to_scale = [f for f in features_to_scale if f in df.columns]
    
    scaler = StandardScaler()
    df[features_to_scale] = scaler.fit_transform(df[features_to_scale])
    
    return df

if __name__ == "__main__":
    DATA_DIR = "/home/outhmane/Desktop/Projet AD/data/"
    OUTPUT_FILE = "/home/outhmane/Desktop/Projet AD/data/processed_ad_events.csv"
    
    # Run pipeline
    raw_df = load_and_merge_data(DATA_DIR)
    if not raw_df.empty:
        cleaned_df = clean_data(raw_df)
        featured_df = extract_features(cleaned_df)
        final_df = encode_and_normalize(featured_df)
        
        # Drops non-numeric/non-useful columns for ML before saving
        # Select Only Numeric columns + attack_type and label
        final_numeric_df = final_df.select_dtypes(include=['number'])
        
        # Ensure we keep the labels and encoded categories
        # (they are already numbers due to LabelEncoder)
        
        # Save to CSV
        print(f"Saving processed dataset to {OUTPUT_FILE}...")
        final_numeric_df.to_csv(OUTPUT_FILE, index=False)
        print("Done!")
    else:
        print("No data found.")
