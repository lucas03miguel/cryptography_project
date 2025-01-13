from flask import current_app
import psycopg2


##########################################################
## DATABASE ACCESS
##########################################################

# Function to connect to the database
def get_db():
    """
    Creates a connection to the PostgreSQL database.
    Returns a connection object that can be used to execute queries.
    """
    db = psycopg2.connect(
        user=current_app.config['DATABASE_USER'],
        password=current_app.config['DATABASE_PASSWORD'],
        host=current_app.config['DATABASE_HOST'],
        port=current_app.config['DATABASE_PORT'],
        database=current_app.config['DATABASE_NAME']
    )
    return db