# utils/predict.py
import joblib
import numpy as np

def load_model_and_scaler():
    """
    Load the trained model, scaler, and feature names from model.pkl
    Returns: model, scaler, feature_names
    """
    model, scaler, feature_names = joblib.load("model.pkl")
    return model, scaler, feature_names

def predict_from_vector(vec, model, scaler=None):
    """
    Predict a PE file vector.
    vec: list/array of features in correct order
    model: trained model
    scaler: optional, if your model was trained with scaling
    Returns: (prediction_int, label)
    """
    vec = np.array(vec).reshape(1, -1)
    if scaler:
        vec_scaled = scaler.transform(vec)
    else:
        vec_scaled = vec
    pred = model.predict(vec_scaled)[0]
    label = "Safe" if pred == 1 else "Malicious"
    return pred, label
