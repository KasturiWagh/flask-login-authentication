from flask import Blueprint, render_template,request, flash,redirect,url_for
from .models import User
from werkzeug.security import generate_password_hash,check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user



auth = Blueprint('auth', __name__)

@auth.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in succesfully', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            
            else:
                flash('Incorrect password try again',category='error')
        else:
            flash('Email does not exit' , category='error')



    return render_template("login.html",user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up',methods=['GET','POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        FirstName = request.form.get('FirstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')


        user = User.query.filter_by(email=email).first()
        if user:
            flash('This email alredy exists', category='error')
        elif len(email) < 4:
            flash('Email mustbe greater than 3 character', category='error')
        elif len(FirstName) < 2:
            flash('firys name  mustbe greater than 1 character', category='error')
        elif password1 != password2:
            flash('password don\'t  mach', category='error')
        elif len(password1) < 7:
            flash('password must be grater than 6 characters', category='error')
        else:
            new_user = User(email = email, first_name=FirstName,password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('account cretade', category='success')
            return redirect(url_for('views.home'))

          
            # add user ti the datavase


    return render_template("signup.html", user=current_user)