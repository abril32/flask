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
      
        
        db = get_db()
        error = None
        if not username:
            error = 'Error! se necesita un nombre de usuario.'
        elif not password:
            error = 'Error! se necesita una contraseña.'
        elif verif_password != password:
            error = 'Error! no coinciden contraseñas.'
        elif not email:
            error = 'Error! es necesario un mail'
        
        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password, email) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), email), 
                )
                db.commit()
            except db.IntegrityError:
                error = f"El usuario {username} ya esta registrado."
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
        email = request.form['nuevo_email']
        db= get_db()
        error = None

        if not email:
            error = 'Es necesario un mail.'
        
        if error is None:
            db.execute(
                'UPDATE user SET email = ? WHERE id = ?', (email, g.user['id'])
            )
            db.commit()
            return redirect(url_for('index'))

        
    return render_template('auth/change.html')
    

@bp.route('/delete', methods=('GET','POST'))
def delete_usuario():
    if request.method == 'POST':
        db= get_db()
        db.execute(
            'DELETE FROM user WHERE id = ?', (g.user['id'],)
        )
        db.commit()
        return logout()

    return render_template('auth/change.html')
    
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

