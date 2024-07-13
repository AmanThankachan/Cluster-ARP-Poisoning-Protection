from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('arpshield.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    attacks = conn.execute('SELECT * FROM attacks').fetchall()
    conn.close()
    return render_template('index.html', attacks=attacks)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
