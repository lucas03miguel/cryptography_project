from flask import Flask, redirect, render_template, request, session, abort, make_response, flash
import logging
from database import get_db
import psycopg2
from markupsafe import escape
import os, logging, hashlib, binascii, subprocess, base64, hmac

from extensions import csrf
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

from datetime import datetime, timedelta, timezone

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
            query = "SELECT password, salt FROM users WHERE username = %s"
            cur.execute(query, (username,))
            result = cur.fetchone()
            conn.close()

            if not result:
                return render_template('login.html', message="Invalid credentials!", message_type="error")

            stored_hash, stored_salt = result
            salt_bytes = binascii.unhexlify(stored_salt.encode('utf-8'))
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100000)
            key_hex = binascii.hexlify(key).decode('utf-8')

            if hmac.compare_digest(key_hex, stored_hash):
                if f'{username}_cert' not in request.form:
                    return render_template("login.html", message="Client certificate not found. New device?", message_type="error")

                client_cert_base64 = request.form[f'{username}_cert']
                client_cert = base64.b64decode(client_cert_base64).decode('utf-8')

                try:
                    with open("/tmp/client_cert.pem", "w") as cert_file:
                        cert_file.write(client_cert)

                    result = subprocess.run(
                        ["openssl", "x509", "-in", "/tmp/client_cert.pem", "-noout", "-subject"],
                        capture_output=True,
                        text=True
                    )
                    subject = result.stdout.strip()

                    if "CN =" in subject:
                        username = subject.split("CN = ")[1].split(",")[0]
                        session["user"] = username
                    else:
                        return render_template("login.html", message="Authentication failed. Please try again.", message_type="error")

                except Exception as e:
                    logger.error(f"Error with client certificate: {str(e)}")
                    return render_template("login.html", message="Error with client certificate.", message_type="error")


                session['user'] = username
                resp = make_response(render_template('login.html', message="Login successful!", message_type="success", redirect=True, redirect_url="/index"))
                if remember == 'on':
                    resp.set_cookie('remembered_username', username, max_age=86400, secure=True, httponly=True, samesite='Strict')
                return resp
            else:
                return render_template('login.html', message="Invalid credentials!", message_type="error")

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return render_template('login.html', message="An error occurred during login. Please try again.", message_type="error")
    
    return render_template("login.html")
    



##########################################################
## Registration
##########################################################
@app.route("/registration", methods=['GET', 'POST'])
def registration():
    session['route'] = 'registration'

    if 'user' in session:
        return redirect("/index")

    if request.method == 'POST':
        username = escape(request.form['username'])
        password = escape(request.form['password'])

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        rows = cur.fetchall()
        conn.close()

        if len(rows) > 0:
            return render_template('registration.html', message="Registration was unsuccessful. Please try again.", message_type="error")

        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        salt_hex = binascii.hexlify(salt).decode('utf-8')
        key_hex = binascii.hexlify(key).decode('utf-8')


        msg_private_key, msg_cert, public_key_pem = generate_certificate(username, usage="Messages")
        save_private_key(username, msg_private_key, key)

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO users (username, password, salt, msg_public_key) 
            VALUES (%s, %s, %s, %s)
            """, 
            (username, key_hex, salt_hex, public_key_pem.decode('utf-8'))
        )
        conn.commit()
        conn.close()

        cert_dir = f"../certificates/clients/{username}"
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)

        client_key = f"{cert_dir}/{username}-key.pem"
        client_csr = f"{cert_dir}/{username}.csr"
        client_cert = f"{cert_dir}/{username}-cert.pem"

        try:
            subprocess.run(["openssl", "genrsa", "-out", client_key, "2048"], check=True)
            subprocess.run(["openssl", "req", "-new", "-key", client_key, "-out", client_csr, "-subj", f"/CN={username}"], check=True)
            subprocess.run(["openssl", "x509", "-req", "-in", client_csr, "-CA", "../certificates/ca.crt", "-CAkey", "../certificates/ca.key", "-CAcreateserial", "-out", client_cert, "-days", "365", "-sha256"], check=True)

        except subprocess.CalledProcessError as e:
            logger.error(f"Error generating certificate for {username}: {e}")
            return render_template('registration.html', message="Error generating certificate. Please try again.", message_type="error")


        with open(client_cert, 'r') as cert_file:
            client_cert_data = cert_file.read()

        encoded_cert = base64.b64encode(client_cert_data.encode('utf-8')).decode('utf-8')

        return render_template('registration.html', message="User registered successfully.", message_type="success", client_cert=encoded_cert, username=username)


    return render_template("registration.html")




##########################################################
## Geração de certificados e chaves para cada utilizador posteriormente usados nos chats
##########################################################

def generate_certificate(username, usage):
    """
    Gera chaves RSA e um certificado assinado pela CA.
    :param username: Nome do utilizador.
    :param usage: Uso da chave ("Authentication" ou "Messages").
    :return: Par chave privada, certificado assinado e chave pública no formato PEM.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    with open("/certificates/ca.key", "rb") as ca_key_file:
        ca_private_key = serialization.load_pem_private_key(
            ca_key_file.read(),
            password=None
        )
    with open("/certificates/ca.crt", "rb") as ca_cert_file:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read())


    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{username} ({usage})"),
        ])
    ).sign(private_key, hashes.SHA256())

    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=(usage == "Messages"),
                content_commitment=True,
                data_encipherment=(usage == "Messages"),
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    public_key_pem = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


    return private_key, cert, public_key_pem


def save_private_key(username, private_key, password):
    """
    Salva uma chave privada num ficheiro protegido por uma senha derivada.
    :param username: Nome do utilizador.
    :param private_key: Objeto de chave privada.
    :param password: Senha derivada (bytes).
    """

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../certificates"))
    user_keys_dir = os.path.join(base_dir, "Message_Userkeys")

    user_dir = os.path.join(user_keys_dir, username)
    os.makedirs(user_dir, exist_ok=True)

    filename = os.path.join(user_dir, f"msg_{username}_private.pem")

    with open(filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        ))




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

    return render_template("index.html", is_authenticated=True)




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

    cur.execute("""
        SELECT sender FROM friend_requests 
        WHERE receiver = %s AND status = 'pending'
    """, (username,))
    friend_requests = [{"sender": row[0]} for row in cur.fetchall()]

    if request.method == 'POST':
        friend_username = escape(request.form['friend_username'])

        if username == friend_username:
            return render_template("addFriends.html", is_authenticated=True, 
                                   message="You cannot send a friend request to yourself.", 
                                   message_type="error", 
                                   friend_requests=friend_requests)

        cur.execute("SELECT * FROM users WHERE username = %s", (friend_username,))
        friend = cur.fetchone()

        if not friend:
            return render_template("addFriends.html", is_authenticated=True, 
                                   message="User does not exist.", 
                                   message_type="error", 
                                   friend_requests=friend_requests)

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

        cur.execute("""
            INSERT INTO friend_requests (sender, receiver, status)
            VALUES (%s, %s, %s)
        """, (username, friend_username, 'pending'))
        conn.commit()

        return render_template("addFriends.html", is_authenticated=True, 
                               message="Friend request sent successfully!", 
                               message_type="success", 
                               friend_requests=friend_requests)

    conn.close()

    return render_template("addFriends.html", is_authenticated=True, friend_requests=friend_requests)



@app.route("/manage_friend_request", methods=["GET", "POST"])
def manage_friend_request():
    if request.method == "GET":
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
        
        # Verificar se já existe uma conversa entre os dois utilizadores
        cur.execute("""
            SELECT conversation_id FROM conversations
            WHERE (user1 = %s AND user2 = %s) OR (user1 = %s AND user2 = %s)
        """, (username, sender, sender, username))
        conversation = cur.fetchone()

        if not conversation:
            # Criar uma nova conversa se não existir
            cur.execute("""
                INSERT INTO conversations (user1, user2) VALUES (%s, %s)
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
@app.route("/talk_with_friends", methods=['GET'])
def talk_with_friends():
    is_authenticated = 'user' in session

    session['route'] = 'talk_with_friends'

    if not is_authenticated:
        return render_template("talkWithFriends.html", is_authenticated=False)

    username = session['user']

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT user2 FROM friends WHERE user1 = %s
        UNION
        SELECT user1 FROM friends WHERE user2 = %s
    """, (username, username))
    friends = cur.fetchall()
    conn.close()

    friends_list = [friend[0] for friend in friends]

    return render_template("talkWithFriends.html", is_authenticated=True, friends=friends_list)


@app.route("/talk_with_friends/<friend>", methods=['GET'])
def talk_with_specific_friend(friend):
    is_authenticated = 'user' in session

    if not is_authenticated:
        return render_template("talkWithFriends.html", is_authenticated=False)

    username = session['user']

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT user2 FROM friends WHERE user1 = %s
        UNION
        SELECT user1 FROM friends WHERE user2 = %s
    """, (username, username))
    friends = cur.fetchall()

    friends_list = [friend[0] for friend in friends]

    cur.execute("""
        SELECT sender, message, signature, sender_encrypted_message, sent_at FROM conversation_messages
        WHERE conversation_id = (
            SELECT conversation_id FROM conversations
            WHERE (user1 = %s AND user2 = %s) OR (user1 = %s AND user2 = %s)
        )
        ORDER BY sent_at
    """, (username, friend, friend, username))

    messages = [
        {
            "sender": msg[0],
            "encrypted_message": bytes(msg[1]),
            "signature": bytes(msg[2]),
            "sender_encrypted_message": bytes(msg[3]),
            "timestamp": msg[4]
        }
        for msg in cur.fetchall()
    ]

    cur.execute("SELECT password FROM users WHERE username = %s", (username,))
    key_hex = cur.fetchone()[0]
    conn.close()

    key = binascii.unhexlify(key_hex)

    private_key_path = os.path.join("/certificates/Message_Userkeys", username, f"msg_{username}_private.pem")
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=key
        )

    decrypted_messages = []
    for msg in messages:
        try:
            if username == msg["sender"]:
                decrypted_message = private_key.decrypt(
                    msg["sender_encrypted_message"],
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            else:
                decrypted_message = private_key.decrypt(
                    msg["encrypted_message"],
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )


            sender_public_key = get_sender_public_key(msg["sender"])

            sender_public_key.verify(
                msg["signature"],
                msg["encrypted_message"],
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            decrypted_messages.append({
                "sender": msg["sender"],
                "message": decrypted_message.decode('utf-8'),
                "timestamp": msg["timestamp"]
            })
        except InvalidSignature:
            logger.error(f"Invalid signature for message from {msg['sender']}")
        except Exception as e:
            logger.error(f"Error processing message from {msg['sender']}: {e}")

    return render_template(
        "talkWithFriends.html",
        is_authenticated=True,
        friends=friends_list,
        selected_friend=friend,
        messages=decrypted_messages
    )



@app.route("/send_message", methods=['GET', 'POST'])
def send_message():
    is_authenticated = 'user' in session
    if not is_authenticated:
        return redirect("/login")

    if request.method == 'GET':
        return redirect("/talk_with_friends")
    
    username = session['user']
    friend = request.form.get('friend')
    message = request.form.get('message')

    if not friend or not message:
        flash("Friend or message is missing.", "error")
        return redirect(f"/talk_with_friends/{friend}")


    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT msg_public_key FROM users WHERE username = %s", (friend,))
    recipient_public_key_pem = cur.fetchone()[0]
    recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode('utf-8'))


    sender_public_key = get_sender_public_key(username)


    encrypted_message = recipient_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


    sender_encrypted_message = sender_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


    cur.execute("SELECT password FROM users WHERE username = %s", (username,))
    key_hex = cur.fetchone()[0]
    key = binascii.unhexlify(key_hex)

    private_key_path = os.path.join("/certificates/Message_Userkeys", username, f"msg_{username}_private.pem")
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=key
        )


    signature = private_key.sign(
        encrypted_message,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


    cur.execute("""
        INSERT INTO conversation_messages (conversation_id, sender, message, signature, sender_encrypted_message)
        VALUES (
            (SELECT conversation_id FROM conversations
             WHERE (user1 = %s AND user2 = %s) OR (user1 = %s AND user2 = %s)),
            %s, %s, %s, %s
        )
    """, (
        username, friend, friend, username,
        username,
        psycopg2.Binary(encrypted_message),      
        psycopg2.Binary(signature),              
        psycopg2.Binary(sender_encrypted_message)
    ))
    conn.commit()
    conn.close()

    return redirect(f"/talk_with_friends/{friend}")




def get_sender_public_key(sender):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT msg_public_key FROM users WHERE username = %s", (sender,))
    public_key_pem = cur.fetchone()[0]
    conn.close()

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        return public_key
    except Exception as e:
        logger.error(f"Failed to load public key for {sender}: {e}")
        raise



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