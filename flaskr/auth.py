import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        verif_password = request.form['verif_password']
        email = request.form ['email']
        nuevo_email= request.form['nuevo_email']
        
        db = get_db()
        error = None
        ##No muestra mensajes de error de username,password,email
        if not username:
            error = 'Error! se necesita un nombre de usuario.'
        elif not password:
            error = 'Error! se necesita una contraseña.'
        elif verif_password != password:
            error = 'Error! no coinciden contraseñas.'
        elif not email:
            error = 'Error! es necesario un mail'
        elif nuevo_email == email:
            error = 'Error! es necesario otro mail'
        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password, verif_password,email) VALUES (?, ?, ?, ?)",
                    (username, generate_password_hash(password), verif_password, email), 
                )
                db.commit()
            except db.IntegrityError:
                error = f"El ususario {username} ya esta registrado."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Nombre de usuario incorrecto.'
        elif not check_password_hash(user['password'], password):
            error = 'Contraseña incorrecta.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.route('/change', methods=('GET','POST'))
def change():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['mail']
        nuevo_email = request.form['nuevo_email']

        db= get_db()
        error = None
        user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

