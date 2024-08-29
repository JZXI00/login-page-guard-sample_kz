from flask import Flask, render_template, request, redirect
import sqlite3
import re

app = Flask(__name__)

failed_login_attempts = {}


@app.route('/')
def home():
	return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():

	username = request.form['username']
	password = request.form['password']


	ip_address = request.remote_addr
	if ip_address in failed_login_attempts and failed_login_attempts[ip_address] >= 3:
		return redirect('/blocked')

	if detect_suspicious_request(username) or detect_suspicious_request(password):
		log_suspicious_request(username, password, ip_address)
		return redirect('/suspicious')

	if detect_sql_injection(username) or detect_sql_injection(password):
		log_sql_injection_attempt(username, password, ip_address)
		return redirect('/injected')

	if detect_xss(username) or detect_xss(password):
		log_xss_request(username, password, ip_address)
		return redirect('/suspicious')


	if authenticate_user(username, password):
		return redirect('/dashboard')

	else:
		if ip_address in failed_login_attempts:
			failed_login_attempts[ip_address] += 1
		else:
			failed_login_attempts[ip_address] = 1
		return redirect('/')


def detect_xss(input_value):
	xss_patterns = [
		r"<script.*?>.*?</script>",
		r"<.*?on\w+.*?>",
	]
	for pattern in xss_patterns:
		if re.search(pattern, input_value, re.IGNORECASE):
			return True

	return False


def detect_sql_injection(input_value):
	sql_injection_patterns = [
		r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)",
		r"('\s*OR\s+'[0-9a-zA-Z_-]+?\s*=\s*[0-9a-zA-Z_-]+?\s*')",
	]

	for pattern in sql_injection_patterns:
		if re.search(pattern, input_value, re.IGNORECASE):
			return True

	return False


def detect_suspicious_request(input_value):
	suspicious_pattern = r"(\w)\1{3,}"

	if re.search(suspicious_pattern, input_value, re.IGNORECASE):
		return True

	return False

def log_xss_request(username, password, ip_address):
    log_message = f"XSS сұрауы анықталды! Логин: {username}, Құпиясөз: {password}, IP адресі: {ip_address}"
    print(log_message)

def log_suspicious_request(username, password, ip_address):
    log_message = f"Күдікті сұрау анықталды! Логин: {username}, Құпиясөз: {password}, IP адресі: {ip_address}"
    print(log_message)

def log_sql_injection_attempt(username, password, ip_address):
	log_message = f"SQL инъекция әрекеті анықталды! Логин: {username}, Құпиясөз: {password}, IP адресі: {ip_address}"
	print(log_message)


def authenticate_user(username, password):

	if username == 'admin' and password == 'password':
		return True


@app.route('/blocked')
def blocked():
	return "Тым көп сәтсіз кіру әрекеттері. Сіздің IP адресыңыз бұғатталды."

@app.route('/suspicious')
def suspicious():
	return "Күдікті әрекет анықталды. Сіздің IP адресыңыз бұғатталды."


@app.route('/injected')
def injected():
	return "SQL инъекциясы анықталды. Сіздің IP адресыңыз бұғатталды!"


@app.route('/dashboard')
def dashboard():
	return "Жүйеге қош келдіңіз!!"


if __name__ == '__main__':
	app.run(debug=True)