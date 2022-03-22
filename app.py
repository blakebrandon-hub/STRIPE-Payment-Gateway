from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from forms import *
from os import environ


app = Flask(__name__)
app.config['SECRET_KEY'] = environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('DATABASE')
app.config['STRIPE_PUBLIC_KEY'] = environ.get('STRIPE_PUBLIC_KEY')
app.config['STRIPE_SECRET_KEY'] = environ.get('STRIPE_SECRET_KEY')
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class CartItem(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.String)
	product_id = db.Column(db.String)


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, 
            method='sha256')

        username = form.username.data.rstrip()
        email= form.email.data.rstrip()

        new_user = User(username=username, email=email, 
            password=hashed_password, admin=0)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()

		if user:

			if check_password_hash(user.password, form.password.data):
				login_user(user, remember = form.remember.data)

				return redirect(url_for('index'))

		return "<h2>Error: Invalid username or password</h2>"

	return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
	logout_user()
	return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
# @login_required
def index():
	return render_template('index.html')

@app.route('/addtocart/<product_id>')
@login_required
def add_to_cart(product_id):
	new_item = CartItem(user_id=current_user.username, product_id=product_id)

	db.session.add(new_item)
	db.session.commit()

	return redirect(url_for('index'))

@app.route('/checkout')
@login_required
def checkout():
	products = CartItem.query.filter_by(user_id=current_user.username).all()

	line_items = []

	for product in products:
		li_dict = {}
		li_dict['price'] = product.product_id
		li_dict['quantity'] = 1
		line_items.append(li_dict)

	try:
		checkout_session = stripe.checkout.Session.create(
			line_items = line_items, 
			mode='payment', 
			success_url='https://your-store-demo.herokuapp.com/success', 
			cancel_url='https://your-store-demo.herokuapp.com/cancel',
		)

	except Exception as e:
		return str(e)

	return redirect(checkout_session.url, code=303)

@app.route('/success')
def success():
	return jsonify({"message": "payment successful"})

@app.route('/cancel')
def cancel():
	return jsonify({"message": "payment cancelled"})


if __name__ == "__main__":
	app.run(host="127.0.0.1", port="8000", debug=True)
