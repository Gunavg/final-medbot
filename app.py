from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import pickle
import pandas as pd
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import os
from datetime import datetime
import uuid

app = Flask(__name__)
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['medbot']
users_collection = db['users']
predictions_collection = db['predictions']

# Load model and encoder
model = pickle.load(open('model/disease_prediction_model.pkl', 'rb'))
encoder = pickle.load(open('model/encoder.pkl', 'rb'))

# Load symptom severity and precaution data
symptom_severity = pd.read_csv(r'E:/NM/final medbot/datasets/Symptom-severity.csv')
symptom_precaution = pd.read_csv(r'E:/NM/final medbot/datasets/symptom_precaution.csv')
symptom_description = pd.read_csv(r'E:/NM/final medbot/datasets/symptom_Description.csv')

# Define follow-up questions based on symptoms
follow_up_questions = {
    'itching': ['Is the itching localized or widespread?', 'Does it worsen at night?'],
    'skin_rash': ['Is the rash red or scaly?', 'Does it appear in patches?'],
    'cough': ['Is the cough dry or productive?', 'How long have you had the cough?'],
    'fever': ['What is the highest temperature recorded?', 'Is the fever constant or intermittent?'],
    'fatigue': ['Does the fatigue interfere with daily activities?', 'Is it accompanied by muscle weakness?'],
    'headache': ['Is the headache throbbing or constant?', 'Do you experience nausea with it?'],
    # Add more based on symptom_severity.csv for high-severity symptoms
}

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('user_info'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = users_collection.find_one({'username': username})
    if user and bcrypt.check_password_hash(user['password'], password):
        session['username'] = username
        session['user_id'] = str(user['_id'])
        return redirect(url_for('user_info'))
    return render_template('login.html', error='Invalid credentials')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if users_collection.find_one({'username': username}):
            return render_template('register.html', error='Username already exists')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'role': 'user'
        })
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/user_info', methods=['GET', 'POST'])
def user_info():
    if 'username' not in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        age = request.form['age']
        gender = request.form['gender']
        session['age'] = age
        session['gender'] = gender
        return redirect(url_for('symptoms'))
    return render_template('user_info.html')

@app.route('/symptoms', methods=['GET', 'POST'])
def symptoms():
    if 'username' not in session:
        return redirect(url_for('home'))
    symptoms = symptom_severity['Symptom'].tolist()
    return render_template('index.html', symptoms=symptoms)

@app.route('/get_follow_up', methods=['POST'])
def get_follow_up():
    selected_symptoms = request.json['symptoms']
    questions = []
    for symptom in selected_symptoms:
        if symptom in follow_up_questions:
            questions.extend([{'symptom': symptom, 'question': q} for q in follow_up_questions[symptom]])
    return jsonify(questions)
@app.route('/predict', methods=['POST'])
def predict():
    if 'username' not in session:
        return redirect(url_for('home'))
    symptoms = request.form.getlist('symptoms')
    follow_up_answers = request.form.getlist('follow_up_answers')
    
    # Create input vector as a DataFrame with feature names
    input_vector = [1 if sym in symptoms else 0 for sym in model.feature_names_in_]
    input_df = pd.DataFrame([input_vector], columns=model.feature_names_in_)
    
    # Predict using DataFrame
    prediction = model.predict(input_df)[0]
    predicted_disease = encoder.inverse_transform([prediction])[0]
    
    # Get description and precautions
    description = symptom_description[symptom_description['Disease'] == predicted_disease]['Description'].iloc[0]
    precautions = symptom_precaution[symptom_precaution['Disease'] == predicted_disease][['Precaution_1', 'Precaution_2', 'Precaution_3', 'Precaution_4']].iloc[0].tolist()
    
    # Store prediction in MongoDB
    prediction_id = str(uuid.uuid4())
    predictions_collection.insert_one({
        'user_id': session['user_id'],
        'username': session['username'],
        'age': session.get('age'),
        'gender': session.get('gender'),
        'symptoms': symptoms,
        'follow_up_answers': follow_up_answers,
        'predicted_disease': predicted_disease,
        'description': description,
        'precautions': precautions,
        'timestamp': datetime.now(),
        'prediction_id': prediction_id
    })
    
    return render_template('result.html', 
                         disease=predicted_disease, 
                         description=description, 
                         precautions=precautions, 
                         symptoms=symptoms, 
                         follow_up_answers=follow_up_answers,
                         prediction_id=prediction_id)
'''@app.route('/predict', methods=['POST'])
def predict():
    if 'username' not in session:
        return redirect(url_for('home'))
    symptoms = request.form.getlist('symptoms')
    follow_up_answers = request.form.getlist('follow_up_answers')
    
    # Create input vector for model
    input_vector = [1 if sym in symptoms else 0 for sym in model.feature_names_in_]
    prediction = model.predict([input_vector])[0]
    predicted_disease = encoder.inverse_transform([prediction])[0]
    
    # Get description and precautions
    description = symptom_description[symptom_description['Disease'] == predicted_disease]['Description'].iloc[0]
    precautions = symptom_precaution[symptom_precaution['Disease'] == predicted_disease][['Precaution_1', 'Precaution_2', 'Precaution_3', 'Precaution_4']].iloc[0].tolist()
    
    # Store prediction in MongoDB
    prediction_id = str(uuid.uuid4())
    predictions_collection.insert_one({
        'user_id': session['user_id'],
        'username': session['username'],
        'age': session.get('age'),
        'gender': session.get('gender'),
        'symptoms': symptoms,
        'follow_up_answers': follow_up_answers,
        'predicted_disease': predicted_disease,
        'description': description,
        'precautions': precautions,
        'timestamp': datetime.now(),
        'prediction_id': prediction_id
    })
    
    return render_template('result.html', 
                         disease=predicted_disease, 
                         description=description, 
                         precautions=precautions, 
                         symptoms=symptoms, 
                         follow_up_answers=follow_up_answers,
                         prediction_id=prediction_id)
'''
@app.route('/download_report/<prediction_id>')
def download_report(prediction_id):
    prediction = predictions_collection.find_one({'prediction_id': prediction_id})
    if not prediction:
        return "Report not found", 404
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    story.append(Paragraph("MedBot Disease Prediction Report", styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Username: {prediction['username']}", styles['Normal']))
    story.append(Paragraph(f"Age: {prediction['age']}", styles['Normal']))
    story.append(Paragraph(f"Gender: {prediction['gender']}", styles['Normal']))
    story.append(Paragraph(f"Date: {prediction['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Predicted Disease: {prediction['predicted_disease']}", styles['Heading2']))
    story.append(Paragraph(f"Description: {prediction['description']}", styles['Normal']))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Symptoms:", styles['Heading3']))
    for symptom in prediction['symptoms']:
        story.append(Paragraph(f"- {symptom}", styles['Normal']))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Follow-up Answers:", styles['Heading3']))
    for answer in prediction['follow_up_answers']:
        story.append(Paragraph(f"- {answer}", styles['Normal']))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Precautions:", styles['Heading3']))
    for precaution in prediction['precautions']:
        story.append(Paragraph(f"- {precaution}", styles['Normal']))
    
    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"report_{prediction_id}.pdf", mimetype='application/pdf')

@app.route('/admin')
def admin():
    if 'username' not in session:
        return redirect(url_for('home'))
    user = users_collection.find_one({'username': session['username']})
    if user.get('role') != 'admin':
        return "Unauthorized", 403
    users = list(users_collection.find({}, {'password': 0}))
    return render_template('admin.html', users=users)

@app.route('/chatbot')
def chatbot():
    if 'username' not in session:
        return redirect(url_for('home'))
    return render_template('chatbot.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=False)