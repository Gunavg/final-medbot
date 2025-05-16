from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
import bcrypt
import re
import random
import string
import uuid
from datetime import datetime, timezone
from bson import ObjectId
import pandas as pd
import csv
import logging
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

# Enable Jinja2 zip filter
app.jinja_env.filters['zip'] = zip

# Set up logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# MongoDB setup
mongo_client = MongoClient('mongodb://localhost:27017')
mongo_db = mongo_client['medical_db']
users_collection = mongo_db['users']
admins_collection = mongo_db['admins']
predictions_collection = mongo_db['predictions']
login_logs_collection = mongo_db['login_logs']

# Collections where your datasets are stored (use actual collection names)
follow_up_collection = mongo_db['follow_up_questions']
disease_desc_collection = mongo_db['disease_description']
precaution_collection = mongo_db['symptom_precaution']
dataset_collection = mongo_db['dataset']

try:
    # Convert MongoDB collections to pandas DataFrames
    follow_up_df = pd.DataFrame(list(follow_up_collection.find()))
    disease_desc_df = pd.DataFrame(list(disease_desc_collection.find()))
    precaution_df = pd.DataFrame(list(precaution_collection.find()))
    dataset_df = pd.DataFrame(list(dataset_collection.find()))

    # Optionally, drop the MongoDB _id column if it exists
    for df in [follow_up_df, disease_desc_df, precaution_df, dataset_df]:
        if '_id' in df.columns:
            df.drop(columns=['_id'], inplace=True)
except Exception as e:
    logger.error(f"Error loading datasets from MongoDB: {e}")
    exit(1)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email, firstname, lastname='', age=None, gender=None, address='', phonenumber='', nationality='', role='user'):
        self.id = str(id)
        self.username = username
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.age = age
        self.gender = gender
        self.address = address
        self.phonenumber = phonenumber
        self.nationality = nationality
        self.role = role

    def get_id(self):
        return self.id

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

class Admin(UserMixin):
    def __init__(self, id, username, role='admin'):
        self.id = str(id)
        self.username = username
        self.role = role

    def get_id(self):
        return self.id

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

@login_manager.user_loader
def load_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if user:
            return User(
                user['_id'],
                user['username'],
                user['email'],
                user['firstname'],
                user.get('lastname', ''),
                user.get('age'),
                user.get('gender'),
                user.get('address', ''),
                user.get('phonenumber', ''),
                user.get('nationality', ''),
                user.get('role', 'user')
            )
        admin = admins_collection.find_one({'_id': ObjectId(user_id)})
        if admin:
            return Admin(admin['_id'], admin['username'])
    except Exception as e:
        logger.error(f"Error loading user: {e}")
        return None
    return None

# Symptom list
feature_names = [
    'small_dents_in_nails', 'loss_of_smell', 'weakness_of_one_body_side', 'loss_of_balance',
    'hip_joint_pain', 'skin_rash', 'polyuria', 'continuous_sneezing', 'palpitations',
    'runny_nose', 'dark_urine', 'swollen_blood_vessels', 'lack_of_concentration', 'cramps',
    'toxic_look_(typhos)', 'redness_of_eyes', 'fast_heart_rate', 'yellow_urine',
    'acute_liver_failure', 'slurred_speech', 'breathlessness', 'anxiety', 'belly_pain',
    'swelled_lymph_nodes', 'dehydration', 'joint_pain', 'nausea', 'excessive_hunger',
    'malaise', 'patches_in_throat', 'neck_pain', 'pain_during_bowel_movements',
    'increased_appetite', 'loss_of_appetite', 'muscle_pain', 'swelling_joints', 'sweating',
    'diarrhoea', 'abdominal_pain', 'abnormal_menstruation', 'internal_itching',
    'history_of_alcohol_consumption', 'fluid_overload', 'scurring', 'headache',
    'swollen_legs', 'constipation', 'back_pain', 'red_spots_over_body', 'brittle_nails',
    'bladder_discomfort', 'extra_marital_contacts', 'altered_sensorium', 'mood_swings',
    'ulcers_on_tongue', 'chest_pain', 'inflammatory_nails', 'stomach_pain',
    'red_sore_around_nose', 'pus_filled_pimples', 'cough', 'pain_behind_the_eyes',
    'painful_walking', 'watering_from_eyes', 'cold_hands_and_feets', 'unsteadiness',
    'chills', 'weight_gain', 'obesity', 'throat_irritation', 'vomiting',
    'blurred_and_distorted_vision', 'coma', 'sunken_eyes', 'distention_of_abdomen',
    'irregular_sugar_level', 'receiving_unsterile_injections', 'dischromic_patches',
    'muscle_wasting', 'spinning_movements', 'passage_of_gases', 'movement_stiffness',
    'depression', 'congestion', 'yellowish_skin', 'mild_fever', 'high_fever',
    'yellowing_of_eyes', 'knee_pain', 'pain_in_anal_region', 'continuous_feel_of_urine',
    'stomach_bleeding', 'shivering', 'receiving_blood_transfusion', 'indigestion',
    'rusty_sputum', 'acidity', 'weakness_in_limbs', 'prominent_veins_on_calf', 'bruising',
    'irritability', 'silver_like_dusting', 'muscle_weakness', 'lethargy',
    'visual_disturbances', 'stiff_neck', 'irritation_in_anus', 'foul_smell_of_urine',
    'burning_micturition', 'bloody_stool', 'enlarged_thyroid', 'blackheads',
    'skin_peeling', 'sinus_pressure', 'weight_loss', 'blood_in_sputum',
    'nodal_skin_eruptions', 'mucoid_sputum', 'yellow_crust_ooze', 'fatigue', 'phlegm',
    'family_history', 'swollen_extremeties', 'spotting_urination', 'dizziness',
    'puffy_face_and_eyes', 'blister', 'restlessness', 'drying_and_tingling_lips',
    'itching', 'swelling_of_stomach'
]

# Quotes
quotes = [
    '“The greatest wealth is health.” – Virgil',
    '“Prevention is better than cure.” – Desiderius Erasmus',
    '“Keep moving forward, even if it’s one step at a time.” – Unknown',
    '“Health is not valued till sickness comes.” – Thomas Fuller',
    '“A healthy outside starts from the inside.” – Robert Urich',
    '“Take care of your body. It’s the only place you have to live.” – Jim Rohn'
]

def get_follow_up_questions(symptoms):
    questions = []
    selected_questions = set()
    for symptom in symptoms:
        symptom = symptom.lower().replace(' ', '_')
        symptom_questions = follow_up_df[follow_up_df['Symptom'].str.lower() == symptom]
        if symptom_questions.empty:
            logger.warning(f"No follow-up questions found for symptom: {symptom}")
            questions.append({
                'question': f"How severe is your {symptom.replace('_', ' ')} on a scale of 1-10?",
                'answer_type': 'numeric',
                'possible_answers': [],
                'weight': 1.0
            })
            continue
        symptom_questions = symptom_questions.sample(frac=1).reset_index(drop=True)
        for _, row in symptom_questions.iterrows():
            question = row['Question']
            if question not in selected_questions:
                selected_questions.add(question)
                questions.append({
                    'question': question,
                    'answer_type': row['Answer_Type'],
                    'possible_answers': row['Possible_Answers'].split(';') if pd.notna(row['Possible_Answers']) else [],
                    'weight': row['Weight']
                })
                break
    if not questions:
        logger.error("No follow-up questions generated for any symptoms.")
    else:
        logger.info(f"Generated follow-up questions: {questions}")
    return questions

def predict_diseases(symptoms, answers, follow_up_questions):
    logger.info(f"Predicting diseases for symptoms: {symptoms}, answers: {answers}")
    symptoms_set = set(s.lower().replace(' ', '_') for s in symptoms)
    disease_scores = []
    
    for _, row in precaution_df.iterrows():
        disease = row['Disease']
        disease_lower = disease.lower()
        try:
            dataset_row = dataset_df[dataset_df['Disease'].str.lower() == disease_lower].iloc[0]
        except IndexError:
            logger.warning(f"Disease {disease} not found in dataset_df")
            continue
        
        disease_symptoms = set()
        for col in [f'Symptom_{i}' for i in range(1, 18)]:
            if pd.notna(dataset_row[col]) and dataset_row[col].strip():
                disease_symptoms.add(dataset_row[col].strip().lower().replace(' ', '_'))
        
        logger.debug(f"Disease: {disease}, Dataset symptoms: {disease_symptoms}")
        overlap = len(symptoms_set & disease_symptoms)
        logger.debug(f"Symptom overlap: {overlap}/{len(disease_symptoms)}")
        if overlap == 0:
            logger.debug(f"No symptom overlap for disease: {disease}")
            continue
        base_score = (overlap / len(disease_symptoms)) * 80
        
        for i, answer in enumerate(answers):
            if i >= len(follow_up_questions):
                break
            question = follow_up_questions[i]['question']
            weight = follow_up_questions[i]['weight']
            answer_type = follow_up_questions[i]['answer_type']
            possible_answers = follow_up_questions[i]['possible_answers']
            if answer_type == 'yes_no' and answer.lower() == 'yes':
                base_score += weight * 10
            elif answer_type == 'numeric':
                try:
                    numeric_answer = float(answer)
                    if numeric_answer > 2:
                        base_score += weight * 10
                except ValueError:
                    logger.warning(f"Invalid numeric answer: {answer}")
            elif answer_type == 'multiple_choice' and answer in possible_answers:
                base_score += weight * 10
        
        if base_score < 30:
            logger.debug(f"Disease {disease} score {base_score} below threshold")
            continue
            
        description = disease_desc_df[disease_desc_df['Disease'].str.lower() == disease_lower]['Description'].iloc[0] if disease_lower in disease_desc_df['Disease'].str.lower().values else 'No description available.'
        precautions = [row[f'Precaution_{i}'] for i in range(1, 5) if pd.notna(row[f'Precaution_{i}']) and row[f'Precaution_{i}'].strip()]
        if not precautions:
            logger.warning(f"No precautions found for {disease}")
        
        disease_scores.append({
            'name': disease,
            'accuracy': min(base_score, 95),
            'description': description,
            'precautions': precautions
        })
    
    disease_scores = sorted(disease_scores, key=lambda x: x['accuracy'], reverse=True)[:3]
    if not disease_scores:
        logger.error("No diseases matched the symptoms.")
        return [{
            'name': 'Unknown',
            'accuracy': 50,
            'description': 'No matching disease found. Please consult a healthcare professional.',
            'precautions': ['Consult a healthcare professional for accurate diagnosis.']
        }]
    logger.info(f"Predicted diseases: {disease_scores}")
    return disease_scores

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form.get('lastname', '')
        email = request.form['email']
        age = request.form['age']
        gender = request.form['gender']
        address = request.form.get('address', '')
        phonenumber = request.form.get('phonenumber', '')
        nationality = request.form.get('nationality', '')
        password = request.form.get('password', '')

        if not firstname or not email or not age or not gender:
            flash('First name, email, age, and gender are required.')
            return redirect(url_for('profile'))
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address.')
            return redirect(url_for('profile'))
        try:
            age = int(age)
            if age < 1 or age > 150:
                raise ValueError
        except ValueError:
            flash('Invalid age. Age must be between 1 and 150.')
            return redirect(url_for('profile'))

        update_data = {
            'firstname': firstname,
            'lastname': lastname,
            'email': email,
            'age': age,
            'gender': gender,
            'address': address,
            'phonenumber': phonenumber,
            'nationality': nationality
        }

        if password:
            password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,}$')
            if not password_regex.match(password):
                flash('Password must be at least 6 characters, including uppercase, lowercase, and digits.')
                return redirect(url_for('profile'))
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            update_data['password_hash'] = password_hash

        users_collection.update_one(
            {'_id': ObjectId(current_user.id)},
            {'$set': update_data}
        )
        flash('Profile updated successfully.')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        identifier = request.form['identifier'].lower()
        password = request.form['password'].encode('utf-8')
        user = users_collection.find_one({'$or': [{'username': identifier}, {'email': identifier}]})
        if user:
            logger.info(f"User found: {user['username']}, checking password...")
            # Handle password_hash as string or bytes
            password_hash = user['password_hash']
            if isinstance(password_hash, str):
                password_hash = password_hash.encode('utf-8')
            if bcrypt.checkpw(password, password_hash):
                user_obj = User(
                    user['_id'],
                    user['username'],
                    user['email'],
                    user['firstname'],
                    user.get('lastname', ''),
                    user.get('age'),
                    user.get('gender'),
                    user.get('address', ''),
                    user.get('phonenumber', ''),
                    user.get('nationality', ''),
                    user.get('role', 'user')
                )
                login_user(user_obj)
                login_logs_collection.insert_one({
                    'user_id': user['_id'],
                    'username': user['username'],
                    'timestamp': datetime.utcnow(),
                    'action': 'login'
                })
                logger.info(f"Login successful for {user['username']}")
                if user.get('role') == 'admin':
                    return redirect(url_for('admin'))
                return redirect(url_for('dashboard'))
            else:
                logger.warning("Password mismatch.")
        else:
            logger.warning(f"No user found for identifier: {identifier}")
        flash('Invalid username/email or password.')
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin'))
    if request.method == 'POST':
        identifier = request.form['username'].lower()
        password = request.form['password'].encode('utf-8')
        admin = admins_collection.find_one({
            '$or': [{'username': identifier}, {'email': identifier}]
        })
        if admin:
            password_hash = admin['password_hash']
            if isinstance(password_hash, str):
                password_hash = password_hash.encode('utf-8')
            if bcrypt.checkpw(password, password_hash):
                admin_obj = Admin(admin['_id'], admin['username'])
                login_user(admin_obj)
                login_logs_collection.insert_one({
                    'user_id': admin['_id'],
                    'username': admin['username'],
                    'timestamp': datetime.utcnow(),
                    'action': 'admin_login'
                })
                return redirect(url_for('admin'))
        flash('Invalid admin username or password.')
    return render_template('admin_login.html')

@app.route('/admin')
@login_required
def admin():
    if not (isinstance(current_user, Admin) or (hasattr(current_user, 'role') and current_user.role == 'admin')):
        flash('Unauthorized access.')
        return redirect(url_for('dashboard'))
    users = list(users_collection.find())
    for user in users:
        user['role'] = user.get('role', 'user')
    admins = list(admins_collection.find())
    for admin in admins:
        admin['role'] = 'admin'
    all_users = users + admins
    predictions = list(predictions_collection.find().sort('created_at', -1).limit(50))
    for pred in predictions:
        user = users_collection.find_one({'_id': pred['user_id']})
        pred['username'] = user['username'] if user else 'Unknown'
    login_logs = list(login_logs_collection.find().sort('timestamp', -1).limit(50))
    return render_template('admin.html', users=all_users, predictions=predictions, login_logs=login_logs, current_user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username'].lower()
        email = request.form['email'].lower()
        password = request.form['password'].encode('utf-8')
        age = request.form['age']
        gender = request.form['gender']
        security_answer1 = request.form['security_answer1']
        security_answer2 = request.form['security_answer2']
        security_answer3 = request.form['security_answer3']
        password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,}$')
        if not password_regex.match(password.decode('utf-8')):
            flash('Password must be at least 6 characters, including uppercase, lowercase, and digits.')
            return redirect(url_for('register'))
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address.')
            return redirect(url_for('register'))
        try:
            age = int(age)
            if age < 1 or age > 150:
                raise ValueError
        except ValueError:
            flash('Invalid age. Age must be between 1 and 150.')
            return redirect(url_for('register'))
        if users_collection.find_one({'username': username}):
            flash('Username already exists.')
            return redirect(url_for('register'))
        if users_collection.find_one({'email': email}):
            flash('Email already exists.')
            return redirect(url_for('register'))
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
        user_id = users_collection.insert_one({
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'security_answer1': security_answer1,
            'security_answer2': security_answer2,
            'security_answer3': security_answer3,
            'firstname': '',
            'age': age,
            'gender': gender
        }).inserted_id
        user = users_collection.find_one({'_id': user_id})
        user_obj = User(user['_id'], username, email, '', age=age, gender=gender)
        login_user(user_obj)
        login_logs_collection.insert_one({
            'user_id': user['_id'],
            'username': username,
            'timestamp': datetime.utcnow(),
            'action': 'register'
        })
        return redirect(url_for('dashboard'))
    return render_template('register.html', username=request.args.get('username', ''))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].lower()
        security_answer1 = request.form.get('security_answer1', '')
        security_answer2 = request.form.get('security_answer2', '')
        security_answer3 = request.form.get('security_answer3', '')
        user = users_collection.find_one({'email': email})
        if not user:
            flash('Email not found.')
            return redirect(url_for('forgot_password'))
        if security_answer1 or security_answer2 or security_answer3:
            if (user['security_answer1'].lower() == security_answer1.lower() and
                user['security_answer2'].lower() == security_answer2.lower() and
                user['security_answer3'].lower() == security_answer3.lower()):
                token = str(uuid.uuid4())
                users_collection.update_one(
                    {'_id': user['_id']},
                    {'$set': {'reset_token': token, 'reset_token_expiry': datetime.utcnow() + pd.Timedelta(hours=1)}}
                )
                return redirect(url_for('reset_password', token=token))
            else:
                flash('Incorrect security answers.')
                return redirect(url_for('forgot_password'))
        return render_template('forgot_password.html', email=email, show_questions=True)
    return render_template('forgot_password.html', show_questions=False)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = users_collection.find_one({
        'reset_token': token,
        'reset_token_expiry': {'$gt': datetime.utcnow()}
    })
    if not user:
        flash('Invalid or expired reset link.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form['password'].encode('utf-8')
        confirm_password = request.form['confirm_password'].encode('utf-8')
        password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,}$')
        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('reset_password', token=token))
        if not password_regex.match(password.decode('utf-8')):
            flash('Password must be at least 6 characters, including uppercase, lowercase, and digits.')
            return redirect(url_for('reset_password', token=token))
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'password_hash': password_hash}, '$unset': {'reset_token': '', 'reset_token_expiry': ''}}
        )
        flash('Password reset successfully. Please login.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/view_user_predictions/<user_id>')
@login_required
def view_user_predictions(user_id):
    logger.info(f"View user predictions: current_user={current_user.username}, is_admin={isinstance(current_user, Admin)}, role={getattr(current_user, 'role', None)}")
    if not (isinstance(current_user, Admin) or (hasattr(current_user, 'role') and current_user.role == 'admin')):
        flash('Unauthorized access.')
        logger.info("Redirecting to dashboard: Unauthorized access")
        return redirect(url_for('dashboard'))
    predictions = list(predictions_collection.find({'user_id': ObjectId(user_id)}).sort('created_at', -1))
    for pred in predictions:
        pred['predicted_diseases'] = pred.get('diseases', [])
    return render_template('user_predictions.html', predictions=predictions)

@app.route('/view_report/<report_id>')
@login_required
def view_report(report_id):
    logger.info(f"View report: current_user={current_user.username}, is_admin={isinstance(current_user, Admin)}, role={getattr(current_user, 'role', None)}")
    prediction = predictions_collection.find_one({'_id': report_id})
    if not prediction:
        flash('Report not found.')
        logger.info("Redirecting to dashboard: Report not found")
        return redirect(url_for('dashboard'))
    # Allow admins to view any report, restrict non-admins to their own reports
    is_admin = isinstance(current_user, Admin) or (hasattr(current_user, 'role') and current_user.role == 'admin')
    if not is_admin and str(prediction['user_id']) != current_user.id:
        flash('Unauthorized access.')
        logger.info("Redirecting to dashboard: Unauthorized access")
        return redirect(url_for('dashboard'))
    if not prediction.get('diseases'):
        flash('Diagnosis not yet complete.')
        logger.info(f"Redirecting to follow_up: Diagnosis incomplete for report_id={report_id}")
        return redirect(url_for('follow_up', prediction_id=report_id))
    prediction['created_at_local'] = prediction['created_at'].replace(tzinfo=timezone.utc).astimezone(tz=None)
    zipped_qa = zip(prediction.get('follow_up_questions', []), prediction.get('follow_up_answers', []))
    return render_template('view_report.html', prediction=prediction, zipped_qa=zipped_qa)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    logger.info(f"Add user: current_user={current_user.username}, is_admin={isinstance(current_user, Admin)}, role={getattr(current_user, 'role', None)}")
    if not (isinstance(current_user, Admin) or (hasattr(current_user, 'role') and current_user.role == 'admin')):
        flash('Unauthorized access.')
        logger.info("Redirecting to dashboard: Unauthorized access")
        return redirect(url_for('dashboard'))
    suggested_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    if request.method == 'POST':
        username = request.form['username'].lower()
        email = request.form['email'].lower()
        password = request.form['password'].encode('utf-8')
        role = request.form['role']
        password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,}$')
        if not password_regex.match(password.decode('utf-8')):
            flash('Password must be at least 6 characters, including uppercase, lowercase, and digits.')
            return render_template('add_user.html', suggested_password=suggested_password, error='Invalid password.')
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address.')
            return render_template('add_user.html', suggested_password=suggested_password, error='Invalid email.')
        if users_collection.find_one({'username': username}) or admins_collection.find_one({'username': username}):
            flash('Username already exists.')
            return render_template('add_user.html', suggested_password=suggested_password, error='Username exists.')
        if users_collection.find_one({'email': email}) or admins_collection.find_one({'email': email}):
            flash('Email already exists.')
            return render_template('add_user.html', suggested_password=suggested_password, error='Email exists.')
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
        if role == 'admin':
            admins_collection.insert_one({
                'username': username,
                'email': email,
                'password_hash': password_hash
            })
        else:
            users_collection.insert_one({
                'username': username,
                'email': email,
                'password_hash': password_hash,
                'firstname': ''
            })
        flash('User added successfully.')
        return redirect(url_for('admin'))
    return render_template('add_user.html', suggested_password=suggested_password)

@app.route('/dashboard')
@login_required
def dashboard():
    predictions = list(predictions_collection.find({'user_id': ObjectId(current_user.id)}).sort('created_at', -1))
    for prediction in predictions:
        prediction['created_at_local'] = prediction['created_at'].replace(tzinfo=timezone.utc).astimezone(tz=None)
    return render_template('dashboard.html', predictions=predictions)

@app.route('/symptoms', methods=['GET', 'POST'])
@login_required
def symptoms():
    if request.method == 'POST':
        input_symptoms = request.form.getlist('symptoms')
        logger.info(f"Received symptoms: {input_symptoms}")
        matched_symptoms = [s for s in input_symptoms if s in feature_names]
        logger.info(f"Matched symptoms: {matched_symptoms}")
        if not matched_symptoms:
            flash('Please select at least one symptom.')
            return redirect(url_for('symptoms'))
        
        follow_up_questions = get_follow_up_questions(matched_symptoms)
        
        prediction_id = str(uuid.uuid4())
        predictions_collection.insert_one({
            '_id': prediction_id,
            'user_id': ObjectId(current_user.id),
            'symptoms': matched_symptoms,
            'follow_up_questions': [q['question'] for q in follow_up_questions],
            'follow_up_answer_types': [q['answer_type'] for q in follow_up_questions],
            'follow_up_possible_answers': [q['possible_answers'] for q in follow_up_questions],
            'follow_up_weights': [q['weight'] for q in follow_up_questions],
            'created_at': datetime.utcnow()
        })
        
        return redirect(url_for('follow_up', prediction_id=prediction_id))
    return render_template('symptoms.html', symptoms=feature_names)

@app.route('/follow_up/<prediction_id>', methods=['GET', 'POST'])
@login_required
def follow_up(prediction_id):
    prediction = predictions_collection.find_one({'_id': prediction_id})
    if not prediction or str(prediction['user_id']) != current_user.id:
        flash('Unauthorized access.')
        return redirect(url_for('dashboard'))
    
    questions = [
        {
            'question': q,
            'answer_type': t,
            'possible_answers': a,
            'weight': w
        }
        for q, t, a, w in zip(
            prediction['follow_up_questions'],
            prediction['follow_up_answer_types'],
            prediction['follow_up_possible_answers'],
            prediction['follow_up_weights']
        )
    ]
    
    if not questions:
        flash('No follow-up questions available. Please try again.')
        return redirect(url_for('symptoms'))
    
    if request.method == 'POST':
        answers = []
        for i in range(len(prediction['follow_up_questions'])):
            answer = request.form.get(f'answer_{i}')
            if not answer:
                flash('Please answer all questions.')
                return redirect(url_for('follow_up', prediction_id=prediction_id))
            answers.append(answer)
        
        diseases = predict_diseases(prediction['symptoms'], answers, questions)
        
        predictions_collection.update_one(
            {'_id': prediction_id},
            {'$set': {
                'diseases': diseases,
                'follow_up_answers': answers,
                'quote': random.choice(quotes)
            }}
        )
        return redirect(url_for('view_report', report_id=prediction_id))
    
    return render_template('follow_up.html', prediction=prediction, questions=questions)

@app.route('/download_report/<report_id>')
@login_required
def download_report(report_id):
    logger.info(f"Download report: current_user={current_user.username}, is_admin={isinstance(current_user, Admin)}, role={getattr(current_user, 'role', None)}")
    prediction = predictions_collection.find_one({'_id': report_id})
    if not prediction:
        flash('Report not found.')
        logger.info("Redirecting to dashboard: Report not found")
        return redirect(url_for('dashboard'))
    # Allow admins to download any report, restrict non-admins to their own reports
    is_admin = isinstance(current_user, Admin) or (hasattr(current_user, 'role') and current_user.role == 'admin')
    if not is_admin and str(prediction['user_id']) != current_user.id:
        flash('Unauthorized access.')
        logger.info("Redirecting to dashboard: Unauthorized access")
        return redirect(url_for('dashboard'))
    if not prediction.get('diseases'):
        flash('Diagnosis not yet complete.')
        logger.info(f"Redirecting to follow_up: Diagnosis incomplete for report_id={report_id}")
        return redirect(url_for('follow_up', prediction_id=report_id))
    
    user = users_collection.find_one({'_id': prediction['user_id']})
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=0.5*inch, rightMargin=0.5*inch, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    elements = []
    
    title_style = ParagraphStyle(
        name='Title',
        fontSize=16,
        textColor=colors.HexColor('#007bff'),
        spaceAfter=12,
        alignment=1
    )
    heading_style = ParagraphStyle(
        name='Heading2',
        fontSize=12,
        textColor=colors.HexColor('#0056b3'),
        spaceBefore=12,
        spaceAfter=6
    )
    normal_style = ParagraphStyle(
        name='Normal',
        fontSize=10,
        leading=12,
        spaceAfter=6
    )
    
    # Caduceus and title in same line
    caduceus_path = os.path.join(app.static_folder, 'caduceus.png')
    title_row = []
    if os.path.exists(caduceus_path):
        caduceus_img = Image(caduceus_path, width=0.5*inch, height=0.5*inch)
        title_row.append(caduceus_img)
    else:
        title_row.append(Paragraph("", normal_style))
    title_row.append(Paragraph("MedBot Diagnosis Report", title_style))
    title_table = Table([title_row], colWidths=[0.7*inch, 6.3*inch])
    title_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('ALIGN', (1, 0), (1, 0), 'CENTER'),
        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
    ]))
    elements.append(title_table)
    elements.append(Spacer(1, 12))
    
    elements.append(Paragraph("Patient Details", heading_style))
    user_data = [
        ["Field", "Value"],
        ["Patient", f"{user.get('firstname', 'Unknown')} {user.get('lastname', '')}".strip() or "Unknown"],
        ["Age", str(user.get('age', 'N/A'))],
        ["Gender", user.get('gender', 'N/A')],
        ["Date", prediction['created_at'].replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y-%m-%d')]
    ]
    user_table = Table(user_data, colWidths=[1.5*inch, 5*inch])
    user_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007bff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(user_table)
    elements.append(Spacer(1, 12))
    
    elements.append(Paragraph("Symptoms", heading_style))
    symptom_data = [["Symptom"]]
    for symptom in prediction['symptoms']:
        symptom_data.append([Paragraph(symptom.replace('_', ' ').capitalize(), normal_style)])
    symptom_table = Table(symptom_data, colWidths=[6.5*inch])
    symptom_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007bff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(symptom_table)
    elements.append(Spacer(1, 12))
    
    elements.append(Paragraph("Follow-Up Questions and Answers", heading_style))
    qa_data = [["Question", "Answer"]]
    for q, a in zip(prediction.get('follow_up_questions', []), prediction.get('follow_up_answers', [])):
        qa_data.append([Paragraph(q, normal_style), Paragraph(a, normal_style)])
    qa_table = Table(qa_data, colWidths=[3.5*inch, 3*inch])
    qa_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007bff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(qa_table)
    elements.append(Spacer(1, 12))
    
    elements.append(Paragraph("Predicted Diseases", heading_style))
    disease_data = [["Disease", "Percentage", "Description"]]
    for disease in prediction['diseases']:
        disease_data.append([
            Paragraph(disease['name'], normal_style),
            Paragraph(f"{round(disease['accuracy'], 2)}%", normal_style),
            Paragraph(disease['description'], normal_style)
        ])
    disease_table = Table(disease_data, colWidths=[1.5*inch, 1*inch, 4*inch])
    disease_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007bff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(disease_table)
    elements.append(Spacer(1, 12))
    
    elements.append(Paragraph("Precautions", heading_style))
    precaution_data = [["Disease", "Precautions"]]
    for disease in prediction['diseases']:
        precautions = ', '.join(disease['precautions']) if disease['precautions'] else 'No precautions available.'
        precaution_data.append([
            Paragraph(disease['name'], normal_style),
            Paragraph(precautions, normal_style)
        ])
    precaution_table = Table(precaution_data, colWidths=[1.5*inch, 5*inch])
    precaution_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007bff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(precaution_table)
    elements.append(Spacer(1, 12))
    
    elements.append(Paragraph(f"“{prediction.get('quote', '')}”", ParagraphStyle(
        name='Quote',
        fontSize=10,
        textColor=colors.black,
        alignment=1,
        spaceBefore=12
    )))
    
    try:
        doc.build(elements)
        pdf = buffer.getvalue()
        buffer.close()
        return Response(
            pdf,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment;filename=report_{report_id}.pdf'}
        )
    except Exception as e:
        logger.error(f'PDF generation failed: {str(e)}')
        flash(f'PDF generation failed: {str(e)}.')
        return redirect(url_for('view_report', report_id=report_id))

@app.route('/logout')
@login_required
def logout():
    login_logs_collection.insert_one({
        'user_id': ObjectId(current_user.id),
        'username': current_user.username,
        'timestamp': datetime.utcnow(),
        'action': 'logout'
    })
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=False, use_reloader=False)