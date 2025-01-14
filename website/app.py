from flask import Flask, redirect, render_template, request, session, abort, make_response, url_for
import logging
from database import get_db
from markupsafe import escape
import os, logging, hashlib, binascii, hmac
from extensions import csrf

app = Flask(__name__)
logger = logging.getLogger('logger')


app.config['SESSION_PERMANENT'] = False


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
    if 'user' in session:
        return redirect("/index")

    if 'route' not in session:
        session['route'] = None

    if not session.get('valid_access') and session['route'] != 'login':
        session['route'] = 'login'
        return redirect("/login")

    session['route'] = 'login'

    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            remember = request.form.get('remember', 'off')

            conn = get_db()
            cur = conn.cursor()
            query = "SELECT password, salt, mfa_enabled, totp_secret FROM users WHERE username = %s"
            cur.execute(query, (username,))
            result = cur.fetchone()
            conn.close()

            if not result:
                return make_response(render_template('login.html', message="Invalid credentials!", message_type="error"))


            stored_hash, stored_salt, mfa_enabled, totp_secret = result
            salt_bytes = binascii.unhexlify(stored_salt.encode('utf-8'))
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100000)
            key_hex = binascii.hexlify(key).decode('utf-8')

            if hmac.compare_digest(key_hex, stored_hash):
                if mfa_enabled:
                    session['mfa_pending'] = username
                    session['totp_secret'] = totp_secret
                    return make_response(render_template('login.html', 
                                                         message="Redirecting to MFA...", 
                                                         message_type="success", 
                                                         redirect=True, 
                                                         redirect_url="/validate_mfa"))

                session['user'] = username
                resp = make_response(render_template('login.html', 
                                                     message="Login successful!", 
                                                     message_type="success", 
                                                     redirect=True, 
                                                     redirect_url="/index"))
                if remember == 'on':
                    resp.set_cookie('remembered_username', username, max_age=86400, secure=True, httponly=True, samesite='Strict')
                return resp
            else:
                return make_response(render_template('login.html', message="Invalid credentials!", message_type="error"))

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return make_response(render_template('login.html', message="An error occurred during login. Please try again.", message_type="error"))
    
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
## Index
##########################################################
@app.route("/index", methods=['GET', 'POST'])
def index():
    is_authenticated = 'user' in session

    session['route'] = 'index'

    if not is_authenticated:
        return render_template("index.html", is_authenticated=False)
    
    username = session['user']
    
    # Fetch MFA status from the database
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT mfa_enabled FROM users WHERE username = %s", (username,))
    result = cur.fetchone()
    conn.close()

    mfa_enabled = result[0] if result else False  # Check if MFA is enabled (True/False)

    return render_template("index.html", is_authenticated=True, mfa_enabled=mfa_enabled)




##########################################################
## MFA
##########################################################
@app.route("/activate_mfa", methods=['GET', 'POST'])
def mfa():
    return """
    <div class="back-button">
        <a href="/index">
            <button type="submit" class="button back-button-style">Back</button>
        </a>
    </div>

    Em desenvolvimento (ou talvez não)
    """




##########################################################
## Add friends
##########################################################
@app.route("/add_friends", methods=['GET', 'POST'])
def add_friends():
    is_authenticated = 'user' in session

    session['route'] = 'add_friends'

    if not is_authenticated:
        return render_template("addFriends.html", is_authenticated=False)

    username = session['user']

    conn = get_db()
    cur = conn.cursor()

    # Obter pedidos de amizade recebidos
    cur.execute("""
        SELECT sender FROM friend_requests 
        WHERE receiver = %s AND status = 'pending'
    """, (username,))
    friend_requests = [{"sender": row[0]} for row in cur.fetchall()]

    if request.method == 'POST':
        friend_username = escape(request.form['friend_username'])

        # Verificar se o utilizador está a tentar adicionar a si próprio
        if username == friend_username:
            return render_template("addFriends.html", is_authenticated=True, 
                                   message="You cannot send a friend request to yourself.", 
                                   message_type="error", 
                                   friend_requests=friend_requests)

        # Verificar se o amigo existe
        cur.execute("SELECT * FROM users WHERE username = %s", (friend_username,))
        friend = cur.fetchone()

        if not friend:
            return render_template("addFriends.html", is_authenticated=True, 
                                   message="User does not exist.", 
                                   message_type="error", 
                                   friend_requests=friend_requests)

        # Verificar se já existe um pedido de amizade pendente
        cur.execute("""
            SELECT * FROM friend_requests 
            WHERE sender = %s AND receiver = %s AND status = 'pending'
        """, (username, friend_username))
        pending_request = cur.fetchone()

        if pending_request:
            return render_template(
                "addFriends.html", 
                is_authenticated=True, 
                message="Friend request already sent and is still pending.", 
                message_type="neutral", 
                friend_requests=friend_requests
            )

        # Verificar se já existe uma amizade entre os dois utilizadores
        cur.execute("""
            SELECT * FROM friends 
            WHERE (user1 = %s AND user2 = %s) OR (user1 = %s AND user2 = %s)
        """, (username, friend_username, friend_username, username))
        friendship = cur.fetchone()

        if friendship:
            return render_template(
                "addFriends.html", 
                is_authenticated=True, 
                message="You are already friends with this user.", 
                message_type="neutral", 
                friend_requests=friend_requests
            )

        # Adicionar pedido de amizade
        cur.execute("""
            INSERT INTO friend_requests (sender, receiver, status)
            VALUES (%s, %s, %s)
        """, (username, friend_username, 'pending'))
        conn.commit()

        # Sucesso
        return render_template("addFriends.html", is_authenticated=True, 
                               message="Friend request sent successfully!", 
                               message_type="success", 
                               friend_requests=friend_requests)

    conn.close()

    # Renderizar a página com os pedidos de amizade recebidos
    return render_template("addFriends.html", is_authenticated=True, friend_requests=friend_requests)



@app.route("/manage_friend_request", methods=["GET", "POST"])
def manage_friend_request():
    if request.method == "GET":
        # Retorna uma mensagem ou redireciona, já que essa rota é para POST.
        return redirect("/add_friends")
    
    if 'route' not in session:
        session['route'] = None

    if not session.get('valid_access') and session['route'] not in ['add_Friends', 'manage_friend_request']:
        return redirect("/add_Friends")
    
    session['route'] = 'manage_friend_request'

    username = session['user']
    sender = escape(request.form['sender'])
    action = request.form['action']

    conn = get_db()
    cur = conn.cursor()

    if action == "accept":
        # Aceitar o pedido: adicionar na tabela de amigos
        cur.execute("""
            INSERT INTO friends (user1, user2) VALUES (%s, %s)
        """, (username, sender))
        
        # Remover o pedido de amizade
        cur.execute("""
            DELETE FROM friend_requests WHERE sender = %s AND receiver = %s
        """, (sender, username))

        # Remover o pedido inverso (caso exista)
        cur.execute("""
            DELETE FROM friend_requests WHERE sender = %s AND receiver = %s
        """, (username, sender))
        
    elif action == "reject":
        # Rejeitar o pedido: apenas remover o pedido de amizade
        cur.execute("""
            DELETE FROM friend_requests WHERE sender = %s AND receiver = %s
        """, (sender, username))

    conn.commit()
    conn.close()

    return redirect("/add_friends")





##########################################################
## Talk with friends
##########################################################
@app.route("/talk_with_friends", methods=['GET', 'POST'])
def talk_with_friends():
    is_authenticated = 'user' in session

    session['route'] = 'index'

    if not is_authenticated:
        return render_template("talkWithFriends.html", is_authenticated=False)
    
    username = session['user']
    
    return render_template("talkWithFriends.html", is_authenticated=True)




##########################################################
## Logout
##########################################################
@app.route('/logout', methods=['GET' ,'POST'])
def logout():

    if not session.get('valid_access') or session['route'] not in ['index']:
        return redirect("/index")

    session['route'] = 'logout'
    session.clear()
    
    resp = redirect('/')
    
    if request.cookies.get('remembered_username'):  
        resp.delete_cookie('remembered_username')
    
    return resp




##########################################################
## MAIN
##########################################################
def main():
    csrf.init_app(app)
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