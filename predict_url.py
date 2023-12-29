from joblib import load
from feature import FeatureExtraction 

def predict_phishing(url):
   
    model = load('phishing_model.joblib')

    feature_extractor = FeatureExtraction(url)
    features_list = feature_extractor.getFeaturesList()

    features_for_prediction = [features_list]

    prediction = model.predict(features_for_prediction)

    probability_scores = model.predict_proba(features_for_prediction)

    return prediction[0], probability_scores[0, 1]  

if __name__ == "__main__":
    url_to_check = "https://www.harvard.edu/" 
                   
    feature_extractor = FeatureExtraction(url_to_check)
    features_list = feature_extractor.getFeaturesList()
    print(features_list)
    result, probability_score = predict_phishing(url_to_check)
    print(f"The URL {url_to_check} is {'phishing' if result == 1 else 'not phishing'}.")
    print(f"Probability Score: {probability_score}")
    