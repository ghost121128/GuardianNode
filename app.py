from flask import Flask, render_template, request, redirect, session, jsonify, send_file
import detector, auth, threading
import pandas as pd
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

# threading.Thread(target=detector.start_sniffing, daemon=True).start()

app = Flask(__name__)
app.secret_key = "guardian_secret"

auth.init_db()
threading.Thread(target=detector.start_sniffing, daemon=True).start()

@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        res = auth.check_user(user, pwd)

        if res:
            session['user'] = user
            session['role'] = res[0]
            return redirect('/dashboard')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')

    with open("logs.txt","r") as f:
        logs = f.readlines()[-50:]

    return render_template('dashboard.html', logs=logs)

@app.route('/stats')
def stats():
    return jsonify({"normal": detector.normal_count, "alerts": detector.alert_count})

@app.route('/timeseries')
def timeseries():
    return jsonify({
        "labels": detector.time_labels,
        "normal": detector.normal_series,
        "alerts": detector.alert_series
    })

@app.route('/distribution')
def distribution():
    return jsonify({
        "ports": list(detector.port_distribution.keys()),
        "counts": list(detector.port_distribution.values())
    })

@app.route('/export/csv')
def csv():
    if session.get('role') != 'admin':
        return "Access Denied"

    df = pd.read_csv("logs.txt", header=None)
    df.to_csv("logs.csv", index=False)
    return send_file("logs.csv", as_attachment=True)

@app.route('/export/pdf')
def pdf():
    if session.get('role') != 'admin':
        return "Access Denied"

    doc = SimpleDocTemplate("logs.pdf")
    styles = getSampleStyleSheet()
    elements = []

    with open("logs.txt") as f:
        for line in f:
            elements.append(Paragraph(line, styles["Normal"]))

    doc.build(elements)
    return send_file("logs.pdf", as_attachment=True)

app.run(debug=True)