import pandas as pd
import numpy as np
import os
import re
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Ensure NLTK resources are downloaded
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords', quiet=True)

try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)

def preprocess_text(text):
    if not isinstance(text, str):
        return ""
    
    # Lowercase
    text = text.lower()
    
    # Remove email headers like 'subject:' or 'from:' at the start of lines to focus on body content
    text = re.sub(r'^(subject|from|to|cc|date):\s*', '', text, flags=re.IGNORECASE)
    
    # Remove URLs (but keep a placeholder or just remove them since we analyze URLs separately)
    # We will replace them with 'httpurl' so the model knows a link was present
    text = re.sub(r'https?://\S+|www\.\S+', 'httpurl', text)
    
    # Remove non-alphabetic characters
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    
    # Tokenize and remove stopwords + apply stemming
    words = text.split()
    stop_words = set(stopwords.words('english'))
    stemmer = PorterStemmer()
    
    cleaned_words = [stemmer.stem(word) for word in words if word not in stop_words]
    
    return " ".join(cleaned_words)

def train_model():
    # File paths
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_path = os.path.join(base_dir, "dataset", "emails.csv")
    models_dir = os.path.join(base_dir, "models")
    
    os.makedirs(models_dir, exist_ok=True)
    
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}. Please run generate_dataset.py first.")
        return
    
    print("Loading dataset...")
    df = pd.read_csv(dataset_path)
    
    print("Preprocessing text data...")
    df['cleaned_text'] = df['text'].apply(preprocess_text)
    
    X = df['cleaned_text']
    y = df['label']
    
    # Split into train and test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print(f"Training set size: {len(X_train)}, Testing set size: {len(X_test)}")
    
    # Vectorize
    print("Vectorizing text using TF-IDF...")
    vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2))
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    # Train Logistic Regression
    print("Training Logistic Regression model...")
    model = LogisticRegression(max_iter=1000, C=1.0, class_weight='balanced')
    model.fit(X_train_vec, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_vec)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Suspicious", "Phishing"]))
    
    # Save model and vectorizer
    model_path = os.path.join(models_dir, "model.pkl")
    vectorizer_path = os.path.join(models_dir, "vectorizer.pkl")
    
    print(f"Saving model to {model_path}...")
    joblib.dump(model, model_path)
    
    print(f"Saving vectorizer to {vectorizer_path}...")
    joblib.dump(vectorizer, vectorizer_path)
    
    print("Model training complete!")

if __name__ == "__main__":
    train_model()
