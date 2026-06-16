# main.py
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from ai_detector import AIDetector, ConfigAnalyzer
from fuzzer.injection_logic import run_injection_scan
from fuzzer.recon import run_recon
import json
import os
from database import *
from fuzzer.owasp import check_outdated_components, check_logging_status, check_auth_indicators, check_misconfigurations, check_cryptographic_failures, check_software_integrity
from flask import make_response, send_file
from datetime import datetime
from urllib.parse import urlparse
from fpdf import FPDF
import io

OWASP_MAPPING = {
    "FORM SQL INJECTION": {"category": "A03:2021-Injection", "severity": "CRITICAL",
                           "details": "SQL Injection detected via DB Error analyzed by NLP Ensemble."},
    "BLIND SQL INJECTION": {"category": "A03:2021-Injection", "severity": "CRITICAL",
                            "details": "Blind SQL Injection detected via structural time delay anomalies."},
    "XSS VULNERABILITY": {"category": "A03:2021-Injection", "severity": "HIGH",
                          "details": "Cross-Site Scripting (XSS) script verified by Random Forest + Naive Bayes."},
    "AUTH_INDICATORS_MISSING": {"category": "A04:2021-Insecure Design / A07 / A08", "severity": "MEDIUM",
                                "details": "Architectural anomaly or secure attributes missing (HttpOnly/Secure/MFA). Classified via MLP Classifier."},
    "CORS_MISCONFIGURATION": {"category": "A05:2021-Security Misconfiguration", "severity": "MEDIUM",
                              "details": "Permissive configuration or sensitive data leak (.env, .git, config)."},
    "OUTDATED_COMPONENTS": {"category": "A06:2021-Vulnerable and Outdated Components", "severity": "HIGH",
                            "details": "Leaked version metadata cross-referenced with CVE vulnerability databases."},
    "INSUFFICIENT_LOGGING": {"category": "A09:2021-Security Logging and Alerting Failures", "severity": "LOW",
                             "details": "Absence of HTTP security headers (CSP, HSTS) blocking threat logging UI."},
    "SSRF_RISK": {"category": "A10:2021-Server-Side Request Forgery (SSRF)", "severity": "HIGH",
                  "details": "URL parameter manipulation attempts targeting internal organization networks."}
}

app = Flask(__name__)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
limiter = Limiter(app=app, key_func=get_remote_address)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

sql_ai = AIDetector('sqli')
xss_ai = AIDetector('xss')
config_analyzer = ConfigAnalyzer()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        success, msg = login_user(username, password)
        if success:
            session['user'] = username
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for('index'))
        flash(msg, "error")
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        success, msg = register_user(username, password)
        if success:
            flash(msg, "success")
            return redirect(url_for('login'))
        flash(msg, "error")
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))



@app.route('/')
def index():
    username = session.get('user', None)
    return render_template('index.html', user=username)


@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login'))
    scans = get_user_scans(session['user'])
    return render_template('history.html', scans=scans)


@app.route('/scan', methods=['POST'])
@limiter.limit("10 per minute")
def scan():
    target_url = request.form.get('url')
    parsed = urlparse(target_url)
    if parsed.scheme not in ['http', 'https']:
        flash("Only HTTP/HTTPS URLs are allowed.", "error")
        return redirect(url_for('index'))

    # Запрещаем сканирование самого себя и внутренних адресов
    blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
    if parsed.hostname in blocked_hosts:
        flash("Scanning internal addresses is not allowed.", "error")
        return redirect(url_for('index'))
    if not target_url:
        return "Please enter a valid target URL", 400


    injection_results = run_injection_scan(target_url, sql_ai, xss_ai)
    recon_results = run_recon(target_url)
    misconfig_results = check_misconfigurations(target_url)
    outdated_results = check_outdated_components(target_url)
    logging_results = check_logging_status(target_url)
    auth_results = check_auth_indicators(target_url)
    crypto_results = check_cryptographic_failures(target_url)  # ← добавь
    integrity_results = check_software_integrity(target_url)


    all_raw_results = (injection_results + recon_results + misconfig_results + outdated_results + auth_results + logging_results + crypto_results + integrity_results)

    processed_results = []
    for bug in all_raw_results:

        bug_type_raw = str(bug.get('type', '')).upper().strip()
        payload = bug.get('payload', 'N/A')


        if bug_type_raw in OWASP_MAPPING:
            owasp_cat = OWASP_MAPPING[bug_type_raw]["category"]
            severity = OWASP_MAPPING[bug_type_raw]["severity"]


            if "SQL" in bug_type_raw:
                is_attack, confidence = sql_ai.predict(payload)
                details = f"SQL Injection detected! AI Confidence: {confidence * 100:.2f}%. Category: {owasp_cat}"
            elif "XSS" in bug_type_raw:
                is_attack, confidence = xss_ai.predict(payload)
                details = f"Cross-Site Scripting found! AI Confidence: {confidence * 100:.2f}%. Category: {owasp_cat}"
            else:

                details = f"{OWASP_MAPPING[bug_type_raw]['details']} Category: {owasp_cat}"
        else:

            owasp_cat = "General Security Risk"
            severity = bug.get('severity', 'LOW')
            details = bug.get('details', 'General vulnerability detected.')


        processed_results.append({
            "type": bug.get('type'),
            "owasp_category": owasp_cat,
            "payload": payload,
            "method": bug.get('method', 'GET').upper(),
            "status_code": bug.get('status_code', 200),
            "severity": severity,
            "details": details
        })


    if 'user' in session:
        save_scan_to_user(session['user'], target_url, processed_results)


    crit_count = sum(1 for b in processed_results if b['severity'] in ['CRITICAL', 'HIGH'])
    med_count = len(processed_results) - crit_count

    return render_template('dashboard.html',
                           target_url=target_url,
                           results=processed_results,
                           crit_count=crit_count,
                           med_count=med_count)




@app.route('/delete_scan', methods=['POST'])
def delete_scan():
    if 'user' not in session:
        return jsonify({"success": False, "error": "Unauthorized endpoint access"})
    data = json.loads(request.data)
    scan_index = data.get('scan_index')
    success, deleted = delete_user_scan(session['user'], scan_index)
    return jsonify({"success": success})


@app.route('/delete_multiple_scans', methods=['POST'])
def delete_multiple_scans():
    if 'user' not in session:
        return jsonify({"success": False, "error": "Unauthorized endpoint access"})
    data = json.loads(request.data)
    scan_indices = data.get('scan_indices', [])
    success, count = delete_user_scans_batch(session['user'], scan_indices)
    return jsonify({"success": success, "deleted_count": count})


@app.route('/download_report', methods=['GET', 'POST'])
def download_report():
    """Generates an executive PDF artifact available without explicit authentication requirements"""
    # Гарантируем наличие необходимых импортов внутри функции
    import io
    import json
    from datetime import datetime

    if request.method == 'GET':
        return "To generate a report, please submit a valid POST request containing scan parameters.", 400

    try:
        target = request.form.get('target', 'unknown')
        results_json = request.form.get('results', '[]')

        try:
            results = json.loads(results_json)
        except Exception as e:
            print(f"JSON Decode Error: {e}")
            results = []

        # Инициализируем FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        # --- 1. ШАПКА ОТЧЕТА (Элегантный корпоративный стиль) ---
        pdf.set_font("helvetica", 'B', 22)
        pdf.set_text_color(26, 37, 48)  # Глубокий сине-черный (#1A2530)
        pdf.cell(0, 15, "SECURITY SCAN REPORT", align='C', ln=True)

        pdf.set_font("helvetica", size=10)
        pdf.set_text_color(98, 125, 152)  # Серый (#627D98)
        pdf.cell(0, 5, f"Target Host: {target}", align='C', ln=True)
        pdf.cell(0, 5, f"Execution Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align='C', ln=True)
        pdf.ln(12)

        # --- 2. ОТРИСОВКА КАРТОЧЕК С УЯЗВИМОСТЯМИ (Все отступы внутри блока try) ---
        for res in results:
            severity = res.get('severity', 'LOW').upper()
            vuln_type = res.get('type', 'Unknown Vulnerability')
            # Мапим owasp_category из твоего роута /scan, если пусто — ищем category
            category = res.get('owasp_category') or res.get('category') or 'General Security Finding'
            details = res.get('details', 'No information provided.')
            payload = res.get('payload', 'N/A')

            # Определяем цвета в зависимости от опасности (RGB)
            if severity in ['HIGH', 'CRITICAL']:
                color_r, color_g, color_b = 211, 47, 47  # Красный
            elif severity == 'MEDIUM':
                color_r, color_g, color_b = 245, 124, 0  # Оранжевый
            else:
                color_r, color_g, color_b = 71, 93, 115  # Стальной серый для Low

            # Сохраняем текущие координаты начала карточки
            start_x = pdf.get_x()
            start_y = pdf.get_y()

            # Фиксированная ширина карточки (чтобы ничего не улетало вправо)
            card_width = 190

            # Считаем примерную высоту, основываясь на длине строк
            lines_details = len(details) // 75 + 1
            lines_payload = len(payload) // 65 + 1
            card_height = 8 + 6 + (lines_details * 5) + (lines_payload * 5) + 12

            # Автоперенос карточки на новую страницу, если она не влезает вниз
            if pdf.get_y() + card_height > 275:
                pdf.add_page()
                start_x = pdf.get_x()
                start_y = pdf.get_y()

            # 1. Задний фон карточки (светло-серый плашка)
            pdf.set_fill_color(245, 247, 250)
            pdf.set_draw_color(228, 231, 235)
            pdf.rect(start_x, start_y, card_width, card_height, style='DF')

            # 2. Левый цветной маркер опасности
            pdf.set_fill_color(color_r, color_g, color_b)
            pdf.rect(start_x, start_y, 4, card_height, style='F')

            # --- Печатаем текст строго внутри нашей карточки ---
            pdf.set_xy(start_x + 8, start_y + 5)

            # Пишем ТИП и СТАТУС в ОДНУ строчку через конкатенацию, контролируя длину
            pdf.set_font("helvetica", 'B', 11)
            pdf.set_text_color(26, 37, 48)
            full_title = f"Type: {vuln_type} [{severity}]"
            pdf.cell(card_width - 12, 5, full_title, ln=True)
            pdf.ln(1)

            # Категория OWASP
            pdf.set_x(start_x + 8)
            pdf.set_font("helvetica", 'B', 9)
            pdf.set_text_color(98, 125, 152)
            pdf.cell(18, 5, "Category: ", ln=False)
            pdf.set_font("helvetica", size=9)
            pdf.set_text_color(51, 78, 104)
            pdf.cell(0, 5, f"{category}", ln=True)
            pdf.ln(1)

            # Описание (Details)
            pdf.set_x(start_x + 8)
            pdf.set_font("helvetica", 'B', 9)
            pdf.set_text_color(98, 125, 152)
            pdf.cell(15, 4, "Details: ", ln=False)

            pdf.set_font("helvetica", size=9)
            pdf.set_text_color(51, 78, 104)
            current_y = pdf.get_y()
            pdf.set_xy(start_x + 23, current_y)
            pdf.multi_cell(card_width - 30, 4, details)
            pdf.ln(1)

            # Технический Пейлоуд (Payload Vector)
            pdf.set_x(start_x + 8)
            pdf.set_font("helvetica", 'B', 9)
            pdf.set_text_color(98, 125, 152)
            pdf.cell(26, 4, "Payload Vector: ", ln=False)

            pdf.set_font("courier", 'B', 9)
            pdf.set_text_color(211, 47, 47)
            current_y = pdf.get_y()
            pdf.set_xy(start_x + 34, current_y)
            pdf.multi_cell(card_width - 40, 4, f"{payload}")

            # Смещаем курсор для следующей карточки
            pdf.set_xy(start_x, start_y + card_height + 6)

        # --- 3. СБОРКА И ОТПРАВКА СГЕНЕРИРОВАННОГО ФАЙЛА ---
        pdf_content = pdf.output(dest='S')

        if isinstance(pdf_content, (bytes, bytearray)):
            pdf_bytes = bytes(pdf_content)
        elif isinstance(pdf_content, str):
            pdf_bytes = pdf_content.encode('latin-1')
        else:
            pdf_bytes = bytes(pdf_content)

        sanitized_filename = target.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')
        filename = f"report_{sanitized_filename}.pdf"

        # Восстанавливаем цвет текста по умолчанию
        pdf.set_text_color(0, 0, 0)

        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        print(f"PDF Generation Error Exception trace: {e}")
        import traceback
        traceback.print_exc()
        return f"Internal Server Error: {str(e)}", 500



@app.route('/docs')
def docs():
    return render_template('docs.html', user=session.get('user'))

@app.route('/owasp')
def owasp():
    return render_template('owasp.html', user=session.get('user'))

@app.route('/export_history')
def export_history():
    if 'user' not in session:
        return redirect(url_for('login'))
    scans = get_user_scans(session['user'])
    import csv, io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Target URL', 'Issues Found'])
    for s in scans:
        writer.writerow([s['date'], s['target'], s['count']])
    output.seek(0)
    from flask import Response
    return Response(output, mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=scan_history.csv"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)