from flask import Flask, redirect, render_template, request, session, abort, make_response
import logging
from database import get_db
from markupsafe import escape
import os, logging, hashlib, binascii, hmac


app = Flask(__name__)
logger = logging.getLogger('logger')


@app.before_request
def restrict_methods():
    allowed_methods = ['GET', 'POST']
    if request.method not in allowed_methods:
        abort(405) 


##########################################################
## Home Page
##########################################################
@app.route("/", methods=['GET', 'POST'])
def home():

    session['valid_access'] = True
    session['route'] = '/'
    
    is_authenticated = 'user' in session
    if is_authenticated:
        return redirect("/index")
    
    remembered_username = request.cookies.get('remembered_username')
    
    if remembered_username:
        logger.info("\nRemembered username found, starting session automatically\n")
        
        session['user'] = remembered_username

        return redirect("/index")
    
    return render_template("open.html")



##########################################################
## Login Page
##########################################################
@app.route("/login", methods=['GET', 'POST'])
def login():
    # Verifica se o utilizador já está autenticado
    if 'user' in session:
        return redirect("/index")

    # Inicializa o estado da sessão, se necessário
    if 'route' not in session:
        session['route'] = None

    # Verifica acesso válido
    if not session.get('valid_access') and session['route'] != 'login':
        session['route'] = 'login'
        return redirect("/login")

    # Atualiza o estado da sessão para "login"
    session['route'] = 'login'

    if request.method == 'POST':
        try:
            # Obtém os dados do formulário
            username = request.form['c_username']
            password = request.form['c_password']
            remember = request.form.get('c_remember', 'off')

            # Consulta a base de dados
            conn = get_db()
            cur = conn.cursor()
            query = "SELECT password, salt, mfa_enabled, totp_secret FROM users WHERE username = %s"
            cur.execute(query, (username,))
            result = cur.fetchone()
            conn.close()

            if not result:
                return make_response(render_template('login.html', message2="Invalid credentials!", message_type="error"))

            # Valida a senha
            stored_hash, stored_salt, mfa_enabled, totp_secret = result
            salt_bytes = binascii.unhexlify(stored_salt.encode('utf-8'))
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100000)
            key_hex = binascii.hexlify(key).decode('utf-8')

            if hmac.compare_digest(key_hex, stored_hash):
                if mfa_enabled:
                    session['mfa_pending'] = username
                    session['totp_secret'] = totp_secret
                    return make_response(render_template('login.html', 
                                                         message2="Redirecting to MFA...", 
                                                         message_type="success", 
                                                         redirect=True, 
                                                         redirect_url="/validate_mfa"))

                session['user'] = username
                resp = make_response(render_template('login.html', 
                                                     message2="Login successful!", 
                                                     message_type="success", 
                                                     redirect=True, 
                                                     redirect_url="/index"))
                if remember == 'on':
                    resp.set_cookie('remembered_username', username, max_age=86400, secure=True, httponly=True, samesite='Strict')
                return resp
            else:
                return make_response(render_template('login.html', message2="Invalid credentials!", message_type="error"))

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return make_response(render_template('login.html', message2="An error occurred during login. Please try again.", message_type="error"))
    
    # Renderiza a página de login no caso de GET
    return render_template("login.html")


##########################################################
## Registration
##########################################################
@app.route("/registration", methods=['GET', 'POST'])
def part1_registration():
    session['route'] = 'registration'

    is_authenticated = 'user' in session
    if is_authenticated:
        return redirect("/index")
    
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = escape(request.form['password'])

        print(f"Username: {username}")
        print(f"Password: {password}")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        rows = cur.fetchall()
        conn.close()

        if len(rows) > 0:
            return render_template('registration.html', message="Registration was unsuccessful. Please try again.", message_type="error")
        else:
            salt = os.urandom(16)

            key = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode('utf-8'), 
                salt, 
                100000
            )
            
            salt_hex = binascii.hexlify(salt).decode('utf-8')
            key_hex = binascii.hexlify(key).decode('utf-8')

            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password, salt) VALUES (%s, %s, %s)", 
                (username, key_hex, salt_hex,)
            )
            conn.commit()
            conn.close()

            return render_template('registration.html', message="User created successfully. Redirecting to login page...", message_type="success")
    
    return render_template("registration.html")


##########################################################
## MAIN
##########################################################
def main():
    app.config.from_object('config.Config')
    logging.basicConfig(filename="logs/log_file.log")

    # Set up logging
    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s:  %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logger.info("Logger initialized...")    
    
    logger.info("Starting the application...")
    app.run(debug=True, threaded=True, host='0.0.0.0', port=5000)


if __name__ == "__main__":
    main()