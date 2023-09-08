from flask import (jsonify, render_template, request,
                   url_for, flash, redirect, session)

from flask import Flask
import os
from pytz import timezone
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from sqlalchemy.sql import text
from flask_login import login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message

from app import app
from app import db
from app import login_manager

from app.models.locker import Locker
from app.models.authuser import AuthUser ,PrivateReserve

import secrets
import string
import pytz
import random
import smtplib
oauth = OAuth(app)
mail = Mail(app)


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our
    # user table, use it in the query for the user
    return AuthUser.query.get(int(user_id))


@app.route('/crash')
def crash():
    return 1/0


@app.route('/db')
def db_connection():
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return '<h1>db works.</h1>'
    except Exception as e:
        return '<h1>db is broken.</h1>' + str(e)


@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data['email']
    otp = generate_otp()
    message = f'Subject: Locker OTP\r\n\r\nYour OTP code is {otp}'

    # send email using SMTP
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    sender_email = 'lockerotp@gmail.com'
    sender_password = 'wvdwjssqsosscaki'

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, email, message)
    server.quit()

    # Store the OTP in the session
    session['otp'] = otp

    # Flash a success message
    # flash('OTP sent successfully!', 'success')

    return 'OTP sent successfully'

def generate_otp():
    # Generate a six-digit random number
    otp = random.randint(100000, 999999)
    return otp


@app.route('/')
def main():
    return app.send_static_file('main.html')
@app.route('/home')
def index():
    return render_template('project/index.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('project/profile.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        # login code goes here
        email = request.form.get('email')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))

        user = AuthUser.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            # if the user doesn't exist or password is wrong, reload the page
            return redirect(url_for('login'))

        login_user(user, remember=remember)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)

    return render_template('project/login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/signup', methods=('GET', 'POST'))
def signup():
    if request.method == 'POST':
        result = request.form.to_dict()
        app.logger.debug(str(result))

        validated = True
        validated_dict = {}
        valid_keys = ['email', 'name', 'password']

        # validate the input
        for key in result:
            app.logger.debug(str(key)+": " + str(result[key]))
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value
            # code to validate and add user to database goes here
        app.logger.debug("validation done")
        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            email = validated_dict['email']
            name = validated_dict['name']
            password = validated_dict['password']
            # if this returns a user, then the email already exists in database
            user = AuthUser.query.filter_by(email=email).first()

            if user:
                # if a user is found, we want to redirect back to signup
                # page so user can try again
                flash('Email address already exists')
                return redirect(url_for('signup'))

            # create a new user with the form data. Hash the password so
            app.logger.debug("preparing to add")
            avatar_url = gen_avatar_url(email, name)
            new_user = AuthUser(email=email, name=name,
                                password=generate_password_hash(
                                    password, method='sha256'),
                                avatar_url=avatar_url)
            # add the new user to the database
            db.session.add(new_user)
            db.session.commit()

        return redirect(url_for('login'))
    return render_template('project/signup.html')

def gen_avatar_url(email, name):
    bgcolor = generate_password_hash(email, method='sha256')[-6:]
    color = hex(int('0xffffff', 0) -
                int('0x'+bgcolor, 0)).replace('0x', '')
    lname = ''
    temp = name.split()
    fname = temp[0][0]
    if len(temp) > 1:
        lname = temp[1][0]

    avatar_url = "https://ui-avatars.com/api/?name=" + \
        fname + "+" + lname + "&background=" + \
        bgcolor + "&color=" + color
    return avatar_url

@app.route('/booking', methods=['POST'])
@login_required
def book_lock():
    if request.method == 'POST':
        result = request.form.to_dict()
        app.logger.debug(str(result))
        id_ = result.get('id', '')
        validated = True
        validated_dict = dict()
        valid_keys = ['stat_date', 'end_date', 'locker_id', "user_id","timezone"]

        # validate the input
        for key in result:
            # app.logger.debug(key, result[key])
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value


    if validated:
        start_date_str = validated_dict['stat_date']
        end_date_str = validated_dict['end_date']
        start_date = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')

        # get the local timezone
        local_tz = pytz.timezone(validated_dict['timezone'])
        # localize the start_date and end_date to the local timezone
        localized_start_date = local_tz.localize(start_date)
        localized_end_date = local_tz.localize(end_date)

        # convert the localized start_date and end_date to UTC timezone
        utc_start_date = localized_start_date.astimezone(pytz.utc)
        utc_end_date = localized_end_date.astimezone(pytz.utc)

        # add the converted dates to the validated_dict
        validated_dict['stat_date']  = utc_start_date
        validated_dict['end_date'] = utc_end_date
        
        # check if locker is available during the requested reservation period
        conflicts = Locker.query.filter_by(locker_id=validated_dict['locker_id']).filter(
        (Locker.stat_date < utc_end_date) &
        (Locker.end_date > utc_start_date)
        ).all()

        if conflicts and not id_:
            app.logger.error('------------------------------------------------------------------')
            app.logger.error(f'Locker {validated_dict["locker_id"]} is already booked for the requested reservation period.')
            flash("This time is already reserved.")
            return 'redirect(url_for(index))'
        elif conflicts and id_:
            # if the user is updating their reservation, check if there are conflicts with other reservations
            for conflict in conflicts:
                if conflict.id != int(id_):
                    app.logger.error('------------------------------------------------------------------')
                    app.logger.error(f'Locker {validated_dict["locker_id"]} is already booked for the requested reservation period.')
                    flash('This time is already reserved.')
                    return 'redirect(url_for(index))'

        # if there is no id: create a new contact entry
        if not id_:
            validated_dict['owner_id'] = current_user.id

            entry = PrivateReserve(**validated_dict)
            app.logger.debug(str(entry))
            db.session.add(entry)
        else:
            contact = PrivateReserve.query.get(id_)
            if contact.owner_id == current_user.id:
                contact.update(**validated_dict)
        
        flash('Sucess!!')
        db.session.commit()

    # return db_locker()
    return redirect(url_for('index'))


def get_all_lockers():
    data = []
    db_locker = Locker.query.all()
    data = list(map(lambda x: x.to_dict(), db_locker))
        
    for item in data:
        local_tz = pytz.timezone(item['timezone'])
        end_utc_time = datetime.strptime(item['end_date'], '%Y-%m-%d %H:%M:%S')  # Convert UTC time string to datetime object
        stat_utc_time = datetime.strptime(item['stat_date'], '%Y-%m-%d %H:%M:%S')  # Convert UTC time string to datetime object
        
        stat_local_time = stat_utc_time.replace(tzinfo=pytz.utc).astimezone(local_tz)
        end_local_time = end_utc_time.replace(tzinfo=pytz.utc).astimezone(local_tz)  # Convert UTC time to local time
        item['stat_date'] = stat_local_time.strftime('%Y-%m-%d %H:%M:%S')  # Convert local time back to string
        item['end_date'] = end_local_time.strftime('%Y-%m-%d %H:%M:%S')  # Convert local time back to string

    data.sort(key=lambda x: x['id'])
    app.logger.debug("All Locker data: " + str(data))
    return data

def get_reserve():
    data = []
    # now = datetime.now()
    utc_now = datetime.utcnow()  # Get current UTC time
    # local_tz = pytz.timezone('Asia/Bangkok')  # Replace 'YOUR_LOCAL_TIMEZONE' with your local timezone name, e.g. 'Europe/London'
    
    db_locker = Locker.query.filter(Locker.end_date >= utc_now)
    data = list(map(lambda x: x.to_dict(), db_locker))
    
    # Convert UTC datetime to local datetime for each reservation
    for item in data:
        local_tz = pytz.timezone(item['timezone'])

        end_utc_time = datetime.strptime(item['end_date'], '%Y-%m-%d %H:%M:%S')  # Convert UTC time string to datetime object
        stat_utc_time = datetime.strptime(item['stat_date'], '%Y-%m-%d %H:%M:%S')  # Convert UTC time string to datetime object
        
        stat_local_time = stat_utc_time.replace(tzinfo=pytz.utc).astimezone(local_tz)
        end_local_time = end_utc_time.replace(tzinfo=pytz.utc).astimezone(local_tz)  # Convert UTC time to local time
        item['stat_date'] = stat_local_time.strftime('%Y-%m-%d %H:%M:%S')  # Convert local time back to string
        item['end_date'] = end_local_time.strftime('%Y-%m-%d %H:%M:%S')  # Convert local time back to string

    data.sort(key=lambda x: x['id'])
    app.logger.debug("DB Blog: " + str(data))
    return data

@app.route('/data')
def db_locker():
    data = get_reserve()
    return jsonify(data)

@app.route('/all_data')
def get_all_data():
    data = get_all_lockers()
    return jsonify(data)

@app.route('/cancle', methods=('GET', 'POST'))
@login_required
def cancle_reserve():
    if request.method == 'POST':
        result = request.form.to_dict()
        id_ = result.get('id', '')
        try:
            contact = PrivateReserve.query.get(id_)
            if contact.owner_id == current_user.id:
                db.session.delete(contact)
            db.session.commit()
        except Exception as ex:
            app.logger.debug(ex)
            raise
    return index()

@app.route('/lab13/submit-form', methods=['POST'])
@login_required
def submit_form():
    new_name = request.form['name']
    new_email = request.form['email']
    new_avatar = request.form['user_pic']
    input_otp = request.form['otp']

    if str(input_otp) == str(session.get('otp')):
        # Update the user's name and email
        current_user.name = new_name
        current_user.email = new_email
        current_user.avatar_url = new_avatar
        db.session.commit()

        flash("Your profile has been updated successfully!")
    else:
        flash("Incorrect OTP, Please try again")
    return redirect(url_for('profile'))


@app.route('/google/')
def google():
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
        client_kwargs={
            'scope': 'openid email profile'
        }
    )
    # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    app.logger.debug("Google token"+str(token))

    userinfo = token['userinfo']
    app.logger.debug(" Google User " + str(userinfo))
    email = userinfo['email']
    user = AuthUser.query.filter_by(email=email).first()

    if not user:
        if 'family_name' in userinfo:
            name = userinfo['given_name'] + " " + userinfo['family_name']
        else:
            name = userinfo['given_name']

        random_pass_len = 8
        password = ''.join(secrets.choice(string.ascii_uppercase + string.digits)
                           for i in range(random_pass_len))
        picture = userinfo['picture']
        new_user = AuthUser(email=email, name=name,
                            password=generate_password_hash(
                                password, method='sha256'),
                            avatar_url=picture)
        db.session.add(new_user)
        db.session.commit()
        user = AuthUser.query.filter_by(email=email).first()
    login_user(user)
    return redirect(url_for('index'))


@app.route('/facebook/')
def facebook():
    # Facebook Oauth Config
    FACEBOOK_CLIENT_ID = os.environ.get('FACEBOOK_CLIENT_ID')
    FACEBOOK_CLIENT_SECRET = os.environ.get('FACEBOOK_CLIENT_SECRET')
    oauth.register(
        name='facebook',
        client_id=FACEBOOK_CLIENT_ID,
        client_secret=FACEBOOK_CLIENT_SECRET,
        access_token_url='https://graph.facebook.com/oauth/access_token',
        access_token_params=None,
        authorize_url='https://www.facebook.com/dialog/oauth',
        authorize_params=None,
        api_base_url='https://graph.facebook.com/',
        client_kwargs={'scope': 'email'},
    )
    redirect_uri = url_for('facebook_auth', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri)


@app.route('/facebook/auth/')
def facebook_auth():
    token = oauth.facebook.authorize_access_token()
    app.logger.debug("facebook token"+str(token))

    resp = oauth.facebook.get(
        'https://graph.facebook.com/me?fields=id,name,email,picture{url}')
    profile = resp.json()
    app.logger.debug("facebook token"+str(profile))
    name = profile["name"]
    email = profile["email"]
    picture = profile["picture"]["data"]["url"]

    user = AuthUser.query.filter_by(email=email).first()

    if not user:
        name = name
        random_pass_len = 8
        password = ''.join(secrets.choice(string.ascii_uppercase + string.digits)
                           for i in range(random_pass_len))
        new_user = AuthUser(email=email, name=name,
                            password=generate_password_hash(
                                password, method='sha256'),
                            avatar_url=picture)
        db.session.add(new_user)
        db.session.commit()
        user = AuthUser.query.filter_by(email=email).first()
    login_user(user)

    return redirect('/home')


