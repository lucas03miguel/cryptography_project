from flask import Flask, redirect, render_template, request, session, abort
from flask_wtf.csrf import CSRFProtect
import logging
from database import get_db


app = Flask(__name__)
logger = logging.getLogger('logger')

csrf = CSRFProtect()

@app.before_request
def restrict_methods():
    allowed_methods = ['GET', 'POST']
    if request.method not in allowed_methods:
        abort(405) 


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


@app.route("/login", methods=['GET', 'POST'])
def login():
    is_authenticated = 'user' in session

    if is_authenticated:
        return redirect("/index")
    
    session['route'] = 'login'

    return render_template("login.html")


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