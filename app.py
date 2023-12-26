from flask import Flask, render_template, request,make_response
from joblib import load
from feature import FeatureExtraction

app = Flask(__name__)

# Load the trained model
model = load('phishing_model.joblib')

@app.route('/', methods=['GET', 'POST'])
def index1():
    result = None

    if request.method == 'POST':
        url_to_check = request.form['url']
        # Extract features for the given URL
        feature_extractor = FeatureExtraction(url_to_check)
        features_list = feature_extractor.getFeaturesList()

        # Reshape the features for prediction
        features_for_prediction = [features_list]

        # Make a prediction
        prediction = model.predict(features_for_prediction)
        probability = model.predict_proba(features_for_prediction)[:, 1]

        result = {
            'url': url_to_check,
            'prediction': 'Phishing' if prediction[0] == 1 else 'Not Phishing',
            'probability':  round(100-probability[0]*100,4)
        }
        
        check=""
        if prediction[0]==1:
            check+="Phishing"
        else:
            check+="Not Phishing"


        response_data=""
        response_data+="URL : "
        response_data+=url_to_check
        response_data+="\n"
        response_data+="Status : "
        response_data+=check
        response_data+="\n"
        response_data+='Percentage safe to use URl is : '
        response_data+=str(round(100-probability[0]*100,4))
        response_data+='\n'
        
        
        file_path='response.txt'
        # for writing in the response.txt file
        with open(file_path,"a") as file:
            file.write("\n"+ response_data)
        
    return render_template('index.html', result=result)

   
if __name__ == '__main__':
    app.run(debug=True)
