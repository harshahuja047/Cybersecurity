from flask import Flask, render_template, request, jsonify
import random
import string

app = Flask(__name__)

def generate_password(length):
    charset = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(charset) for _ in range(length))
    return password

def analyze_password(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1

    if score == 5:
        return "Very Strong"
    elif score == 4:
        return "Strong"
    elif score == 3:
        return "Medium"
    else:
        return "Weak"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    length = int(request.form['length'])
    password = generate_password(length)
    return jsonify(password=password)

@app.route('/analyze', methods=['POST'])
def analyze():
    password = request.form['password']
    analysis = analyze_password(password)
    return jsonify(analysis=analysis)

if __name__ == '__main__':
    app.run(debug=True)
