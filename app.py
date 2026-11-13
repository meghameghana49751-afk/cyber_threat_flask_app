import os
import json
import sqlite3
from datetime import datetime
from bs4 import BeautifulSoup
import requests
import urllib.parse
import base64 
from urllib.parse import urljoin
import controller
import json
import html
import model
import PE_main as filedetection
import os
import random
import sqlite3
from sklearn.metrics import f1_score
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score

from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash

from ipmodel import EnhancedIPAnomalyDetector
import test as email_detection

UPLOAD_FOLDER = './static/Uploads/'

APP_DIR = os.path.abspath(os.path.dirname(__file__))

def create_app():
    app = Flask(__name__)
    # IMPORTANT: set a strong secret in production via env var
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    # SQLite DB under instance/
    instance_dir = os.path.join(APP_DIR, "instance")
    os.makedirs(instance_dir, exist_ok=True)
    app.config["DATABASE"] = os.path.join(instance_dir, "app.db")

    # Model artifacts
    app.config["MODEL_PKL"] = os.path.join(APP_DIR, "enhanced_ip_anomaly_detector.pkl")
    app.config["DATASET_CSV"] = os.path.join(APP_DIR, "AWS_Honeypot_marx-geo.csv")

    # ---------------- DB helpers ----------------
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                input_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                overall_anomaly INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            """
        )
        db.commit()

    @app.before_request
    def _ensure_db():
        init_db()

    # ---------------- Auth helpers ----------------
    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login first.", "warning")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def current_user():
        if "user_id" not in session:
            return None
        db = get_db()
        return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    # ---------------- Model loader ----------------
    # We keep one detector instance cached in app config for speed.
    def get_detector():
        det = app.config.get("_DETECTOR")
        if det is not None:
            return det

        detector = EnhancedIPAnomalyDetector()

        # Try load existing trained artifact; if not available, train from CSV and save.
        try:
            detector.load_models(app.config["MODEL_PKL"])
            app.config["_DETECTOR"] = detector
            return detector
        except Exception:
            # Train if pickle doesn't exist or cannot be loaded
            csv_path = app.config["DATASET_CSV"]
            if not os.path.exists(csv_path):
                raise RuntimeError(
                    "Dataset CSV not found. Put AWS_Honeypot_marx-geo.csv next to app.py"
                )

            df = detector.load_and_preprocess_data(csv_path)
            if df is None:
                raise RuntimeError("Failed to load dataset CSV.")

            detector.train_models(df)
            detector.save_models(app.config["MODEL_PKL"])
            app.config["_DETECTOR"] = detector
            return detector

    # ---------------- Routes ----------------
    @app.get("/")
    def landing():
        return render_template("landing.html", user=current_user())

    @app.get("/register")
    def register():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return render_template("register.html")

    @app.post("/register")
    def register_post():
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("register"))

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?,?,?,?)",
                (name, email, generate_password_hash(password), datetime.utcnow().isoformat()),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for("login"))

        flash("Registered successfully. Please login.", "success")
        return redirect(url_for("login"))

    @app.get("/login")
    def login():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for("login"))

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

        session.clear()
        session["user_id"] = user["id"]
        flash("Logged in successfully.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/logout")
    def logout():
        session.clear()
        flash("Logged out.", "info")
        return redirect(url_for("landing"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        user = current_user()
        db = get_db()
        total = db.execute("SELECT COUNT(*) AS c FROM runs WHERE user_id=?",(user["id"],)).fetchone()["c"]
        last = db.execute("SELECT * FROM runs WHERE user_id=? ORDER BY id DESC LIMIT 1",(user["id"],)).fetchone()
        print(dict(last) if last else "No data")
        return render_template("dashboard.html",user=user,total_runs=total,last_run=last)

    @app.get("/input")
    @login_required
    def input_page():
        return render_template("input.html")

    @app.post("/input")
    @login_required
    def input_post():
        # These fields map 1:1 to model.py create_ip_data_from_input()
        try:
            form = {
                "ip_address": request.form.get("ip_address", "").strip(),
                "total_attacks": int(request.form.get("total_attacks", "0")),
                "unique_dest_ports": int(request.form.get("unique_dest_ports", "0")),
                "unique_src_ports": int(request.form.get("unique_src_ports", "0")),
                "unique_protocols": int(request.form.get("unique_protocols", "0")),
                "unique_attack_types": int(request.form.get("unique_attack_types", "0")),
                "unique_hosts": int(request.form.get("unique_hosts", "0")),
                "attack_duration_days": float(request.form.get("attack_duration_days", "0")),
                "attacks_per_day": float(request.form.get("attacks_per_day", "0")),
                "distance_from_ref_km": float(request.form.get("distance_from_ref_km", "0")),
                "attack_time_variance": float(request.form.get("attack_time_variance", "0")),
                "common_ports_ratio": float(request.form.get("common_ports_ratio", "0")),
            }
        except ValueError:
            flash("Please enter valid numbers for numeric fields.", "danger")
            return redirect(url_for("input_page"))

        if not form["ip_address"]:
            flash("IP Address is required.", "danger")
            return redirect(url_for("input_page"))

        # Predict using the ML detector
        detector = get_detector()
        ip_data = detector.create_ip_data_from_input(form)
        result = detector.predict_single_ip(ip_data)

        overall = 1 if bool(result.get("overall_anomaly")) else 0

        # Save to DB
        db = get_db()
        cur = db.execute(
            "INSERT INTO runs (user_id, input_json, result_json, overall_anomaly, created_at) VALUES (?,?,?,?,?)",
            (session["user_id"], json.dumps(form), json.dumps(result), overall, datetime.utcnow().isoformat()),
        )
        db.commit()

        run_id = cur.lastrowid
        return redirect(url_for("result", run_id=run_id))

    @app.get("/result/<int:run_id>")
    @login_required
    def result(run_id: int):
        db = get_db()
        row = db.execute(
            "SELECT * FROM runs WHERE id=? AND user_id=?",
            (run_id, session["user_id"]),
        ).fetchone()
        if row is None:
            flash("Result not found.", "warning")
            return redirect(url_for("history"))

        input_data = json.loads(row["input_json"])
        result_data = json.loads(row["result_json"])
        return render_template("result.html", run=row, input_data=input_data, result=result_data)

    @app.get("/history")
    @login_required
    def history():
        db = get_db()
        rows = db.execute(
            "SELECT id, created_at, overall_anomaly, result_json FROM runs WHERE user_id=? ORDER BY id DESC",
            (session["user_id"],),
        ).fetchall()

        # Build light summary for table
        runs = []
        for r in rows:
            try:
                res = json.loads(r["result_json"])
            except Exception:
                res = {}
            runs.append({
                "id": r["id"],
                "created_at": r["created_at"],
                "overall_anomaly": r["overall_anomaly"],
                "kmeans_conf": (res.get("kmeans", {}).get("confidence")),
                "gmm_conf": (res.get("gmm", {}).get("confidence")),
            })
        return render_template("history.html", runs=runs)
    @app.route('/emailpred', methods=['GET','POST'])
    @login_required
    def emailpred():
        if request.method == "POST":
            email = request.form['email_text']
            res = email_detection.detect_spamemail(email)
            print("Email Detection Result:", res)
            return render_template('email_detection.html',output=res)
        return render_template('email_detection.html')

    @app.route('/preview', methods=['POST'])
    @login_required
    def preview():
        try:
            url = request.form.get('url')
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            # inject external resources into HTML
            for link in soup.find_all('link'):
                if link.get('href'):
                    link['href'] = urljoin(url, link['href'])
            for img in soup.find_all('img'):
                if img.get('src'):
                    img['src'] = urljoin(url, img['src'])
            return render_template('preview.html', content=soup.prettify())
        except Exception as e:
            return f"Error: {e}"
    @app.route('/source-code', methods=['GET', 'POST'])
    @login_required
    def view_source_code():
        try:
            url = request.form.get('url')
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            formatted_html = soup.prettify()
            return render_template('source_code.html', formatted_html=formatted_html, url=url)
        except Exception as e:
            return f"Error: {e}"
    @app.route("/filepred", methods=['GET', 'POST'])
    @login_required
    def filepred():
        if request.method == 'POST':
            uploaded_file = request.files['file']
            filename = uploaded_file.filename
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            uploaded_file.save(file_path)
            res = filedetection.process(file_path)
            print("final result==", str(res))
            return render_template("file_detection.html", output=res)
        output = "NA"
        return render_template("file_detection.html", output=output)
    @app.route('/urlpred', methods=['GET', 'POST'])
    @login_required
    def urlpred():
        if request.method == 'POST':
            try:
                url = request.form['url']
                result = controller.main(url)
                output = result               # this is your dict
                print("output==",output)
                if 'response_status' in output:
                    try:
                        if isinstance(output['response_status'], str):
                            import re
                            status_match = re.search(r'\d+', output['response_status'])
                            if status_match:
                                output['response_status'] = int(status_match.group())
                            else:
                                output['response_status'] = 0
                        elif output['response_status'] is False:
                            output['response_status'] = 404
                    except:
                        output['response_status'] = 0
            except Exception as e:
                print("Error in urlpred:", e)
                output = {'res': 'NA', 'response_status': 0, 'trust_score': 0}
            res_value = str(output.get('res', 'NA'))
            print("output['res'] = ", res_value)
            if 'response_status' not in output:
                output['response_status'] = 0
            if res_value.lower() == "malware":
                mes = "Your entered URL " + url + " is Malware"
                res_value = "malware"
            print("res_value==",res_value)
            return render_template('url_detection.html', output=output, res=res_value, url=url)
        else:
            return render_template('url_detection.html')

    @app.template_filter('status_class')
    def status_class_filter(status_code):
        try:
            if status_code:
                code = int(status_code)
                return str(code // 100)
        except:
            pass
            return 'unknown'


    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
