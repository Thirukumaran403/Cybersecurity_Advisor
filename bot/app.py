from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
import os
import json
import base64
import re

app = Flask(__name__)
app.secret_key = 'your-very-secret-key-12345'
# API KEYS
OPENROUTER_API_KEY = 'your-api-key'
VIRUSTOTAL_API_KEY = 'your-api-key'

# File to store user data
USERS_FILE = 'users.json'

# ---------------------- Utility Functions ----------------------

def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def query_openrouter(prompt, role):
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "openai/gpt-3.5-turbo",
        "messages": [
            {"role": "system", "content": role},
            {"role": "user", "content": prompt}
        ]
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            result = response.json()
            if 'choices' in result and len(result['choices']) > 0:
                choice = result['choices'][0]
                if 'message' in choice and 'content' in choice['message']:
                    return choice['message']['content'].strip()
        return "Sorry, something went wrong."
    except requests.exceptions.RequestException:
        return "Sorry, something went wrong."

def is_unclear_input(message):
    words = message.split()
    return len(words) < 2

def heuristic_url_check(url):
    suspicious_patterns = [
        r"free", r"bonus", r"login", r"verify", r"update",
        r"account", r"bank", r"\.zip$", r"\.exe$",
        r"@|%", r"bit\.ly", r"tinyurl", r"grab", r"offer"
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

# ---------------------- Routes ----------------------

@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            return render_template('register.html', error='Please fill in all fields.')

        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match.')

        users = load_users()
        if username in users:
            return render_template('register.html', error='Username already exists.')

        users[username] = password
        save_users(users)

        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        users = load_users()
        if username in users and users[username] == password:
            session['user'] = username
            return redirect('/choose')
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/choose')
def choose():
    if 'user' not in session:
        return redirect('/login')
    return render_template('choose.html')

@app.route('/chatbot')
def chatbot():
    if 'user' not in session:
        return redirect('/login')
    return render_template('chatbot.html')

@app.route('/shield')
def shield():
    if 'user' not in session:
        return redirect('/login')
    return render_template('shieldbot.html')

@app.route('/cyberedu')
def cyberedu():
    if 'user' not in session:
        return redirect('/login')
    return render_template('cyberedu.html')

@app.route('/linkchecker')
def linkchecker():
    if 'user' not in session:
        return redirect('/login')
    return render_template('malicious.html')

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message', '').strip().lower()

    if "who are you" in user_message:
        reply = "I am LegalBridge⚖️, Your AI Legal Assistant who assists you with laws."
    elif is_unclear_input(user_message):
        reply = "Could you please make the scenario more clear?"
    else:
        prompt = f"User described a cyber scenario: '{user_message}'. Provide the cyber laws section and act name from different countries (India, USA, UK) related to the given scenario."
        reply = query_openrouter(prompt, "You are a legal assistant.")

    return jsonify({'reply': reply if reply else 'Sorry, something went wrong.'})

@app.route('/action-bot', methods=['POST'])
def action_bot():
    data = request.get_json()
    user_message = data.get('message', '').strip().lower()

    if "who are you" in user_message:
        reply = "I am S.H.I.E.L.D🛡️, Your AI Assistant who assists you with immediate action and prevention."
    elif is_unclear_input(user_message):
        reply = "Could you please make the scenario more clear?"
    else:
        prompt = f"User described a cyber incident: '{user_message}'. Provide immediate actions and prevention tips."
        reply = query_openrouter(prompt, "You are an assistant providing Immediate Actions and Prevention Tips.")

    return jsonify({'reply': reply if reply else 'Unable to process your request at the moment.'})

@app.route('/edu-bot', methods=['POST'])
def edu_bot():
    data = request.get_json()
    user_message = data.get('message', '').strip().lower()

    if "who are you" in user_message:
        reply = "I am CyberEdu🎓, your Cybersecurity Learning Assistant!"
    elif is_unclear_input(user_message):
        reply = "Could you please make your query more clear?"
    else:
        prompt = f"User asked: '{user_message}'. Explain it very simply."
        reply = query_openrouter(prompt, "You are a cybersecurity teacher.")

    return jsonify({'reply': reply if reply else 'Unable to process your request at the moment.'})

@app.route('/check_link', methods=['POST'])
def check_link():
    data = request.get_json()
    url_to_check = data.get('url', '').strip()

    if not url_to_check:
        return jsonify({'error': '❌ No URL provided. Please enter a valid one.'})

    # Heuristic Check
    if heuristic_url_check(url_to_check):
        return jsonify({'result': '⚠️ This URL appears suspicious based on common phishing patterns!'})

    try:
        # Encode URL to base64 (URL safe)
        url_bytes = url_to_check.encode('utf-8')
        base64_url = base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip('=')

        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        vt_url = f"https://www.virustotal.com/api/v3/urls/{base64_url}"

        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

            if stats.get('malicious', 0) > 0:
                return jsonify({'result': '❌ This URL is flagged as *malicious* by VirusTotal! Do NOT click.'})
            elif stats.get('suspicious', 0) > 0:
                return jsonify({'result': '⚠️ This URL is flagged as *suspicious*. Proceed with caution.'})
            else:
                return jsonify({'result': '✅ This URL appears clean based on VirusTotal analysis.'})
        else:
            return jsonify({'error': '⚠️ This is not an proper URL'})

    except Exception as e:
        return jsonify({'error': f'❌ An error occurred while checking the link: {str(e)}'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ---------------------- Main ----------------------

if __name__ == '__main__':
    app.run(debug=True)
