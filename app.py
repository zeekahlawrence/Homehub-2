from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


app = Flask(__name__)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['SECRET_KEY'] = 'SECRET102'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' 
app.secret_key = 'super_secret_key'



db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Property(db.Model):
     id = db.Column(db.Integer, primary_key=True)
     user_id = db.Column(db.Integer, nullable=False)

     full_name = db.Column(db.String(100))
     email = db.Column(db.String(100))
     phone = db.Column(db.String(20))

     property_type = db.Column(db.String(100))
     address = db.Column(db.String(100))
     price = db.Column(db.Integer)
     bathroom = db.Column(db.Integer)
     bedroom = db.Column(db.Integer)
     description = db.Column(db.Text)
     images = db.Column(db.Text)

class Rentproperty(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)

    fname = db.Column(db.String(100))
    mail = db.Column(db.String(100))
    pnum = db.Column(db.String(20))

    htype = db.Column(db.String(100))
    address = db.Column(db.String(100))
    price = db.Column(db.Integer)
    bathroom = db.Column(db.Integer)
    bedroom = db.Column(db.Integer)
    description = db.Column(db.Text)
    images = db.Column(db.Text)

with app.app_context():
    db.create_all()

@app.route('/home')
def home():

   
    return render_template(
        'index.html'
        
    )

    

@app.route('/buy')

def buy():
    
    properties = Property.query.all()
    return render_template('buy.html', properties=properties)

@app.route('/buy-property/<int:id>')
def buy_property(id):
    if 'user_id' not in session:
        flash("please login to continue")
        return redirect(url_for('login'))
    
    property = Property.query.get_or_404(id)
    return render_template('property_details.html', property=property, type="buy")
    
@app.route('/property/<int:id>')
def property_details(id):
    if 'user_id' not in session:
        flash("please login to view details")
        return redirect(url_for('login'))
 
    property = Property.query.get_or_404(id)
    return render_template('property_details.html', property=property, type="buy")

@app.route('/delete/<int:id>')
def delete_property(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    prop = Property.query.get_or_404(id)

    if prop.user_id != session['user_id']:
        flash("you cannot delete this property")
        return redirect(url_for('buy'))
    
    db.session.delete(prop)
    db.session.commit()
    flash("property deleted")
    return redirect(url_for('buy'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/sell', methods=['GET', 'POST'])

def sell():
    if request.method == 'POST':
        #REQUIRE LOGIN ONLY WHEN SUBMITTING
        if 'user_id' not in session:
            flash("please login to submit a property")
            return redirect(url_for('login'))
        
        if session.get('role') not in ['seller', 'both']:
            flash("Only sellers can submit properties for sale")
            return redirect(url_for('sell'))
        
        image_files = request.files.getlist('images')
        filenames = []

        for file in image_files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                filenames.append(filename)
        
        new_property = Property(
            user_id = session['user_id'],
            full_name = request.form.get('fullname'),
            email = request.form.get('email'),
            phone = request.form.get('phone'),
            property_type = request.form.get('ptype'),
            address = request.form.get('address'),
            price = request.form.get('price'),
            bedroom = request.form.get('bedroom'),
            bathroom = request.form.get('bathroom'),
            description = request.form.get('description'),
            images = ",".join(filenames)

        )

        db.session.add(new_property)
        db.session.commit()

        flash("property submitted successfully")
        return redirect(url_for('buy'))
    return render_template('sell.html')

@app.route('/rent', methods = ['GET', 'POST'])

def rent():
    if request.method == 'POST':
        #REQUIRE LOGIN ONLY WHEN SUBMITTING
        if 'user_id' not in session:
            flash("please login to submit a property")
            return redirect(url_for('login'))
        
        if session.get('role') not in ['seller', 'buyer', 'both']:
            flash("Only sellers can submit properties for sale")
            return redirect(url_for('sell'))
        
        image_files = request.files.getlist('images')
        filenames = []

        for file in image_files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                filenames.append(filename)
        
        new_rent = Rentproperty(
            user_id = session['user_id'],
            fname = request.form.get('fullname'),
            mail = request.form.get('email'),
            pnum = request.form.get('phone'),
            htype = request.form.get('ptype'),
            address = request.form.get('address'),
            price = request.form.get('price'),
            bedroom = request.form.get('bedroom'),
            bathroom = request.form.get('bathroom'),
            description = request.form.get('description'),
            images = ",".join(filenames)

        )

        db.session.add(new_rent)
        db.session.commit()

        flash("property submitted successfully")
        return redirect(url_for('rent'))


    proper = Rentproperty.query.all()
    return render_template('rent.html', properties=proper)

@app.route('/rent-property/<int:id>')
def rent_property(id):
    if 'user_id' not in session:
        flash("please login to continue")
        return redirect(url_for('login'))
    
    property = Rentproperty.query.get_or_404(id)
    return render_template('rent_details.html', property=property)
    
@app.route('/rentproperty/<int:id>')
def rent_property_details(id):
    if 'user_id' not in session:
        flash("please login to view details")
        return redirect(url_for('login'))
 
    property = Rentproperty.query.get_or_404(id)
    return render_template('property_details.html', property=property)

@app.route('/rentdelete/<int:id>')
def delete_rent_property(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    prop = Rentproperty.query.get_or_404(id)

    if prop.user_id != session['user_id']:
        flash("you cannot delete this property")
        return redirect(url_for('rent'))
    
    db.session.delete(prop)
    db.session.commit()
    flash("property deleted")
    return redirect(url_for('rent'))

@app.route('/search')
def search():
    q = request.args.get('q')

    results = Property.query.filter(
        Property.address.ilike(f"%{q}%") |
        Property.property_type.ilike(f"%{q}%")
    ).all()

    return render_template('buy.html', properties=results)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form.get('password')
        cpassword = request.form.get('cpassword')
        role = request.form.get('role')
        if not role:
            flash("please select a role")
            return redirect(url_for('register'))

        if password != cpassword:
            flash("passwords do not match")
            return redirect(url_for('register'))
        
        if Users.query.filter_by(username=username).first():
            flash("username already exists")
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)

        new_user = Users(
            username = username,
            password = hashed_password,
            role = role
        )

        db.session.add(new_user)
        db.session.commit()

        flash("registration successful. pls login")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = Users.query.filter_by(username = username).first()

        if user and check_password_hash(user.password, password):
            session.clear()
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('home'))
        
        flash("invalid username or password")
    return render_template('login.html')
 
@app.route('/logout')
def logout():
    session.clear()
    flash("logged out successfully")
    return redirect(url_for('login'))
           

if __name__ == '__main__':
    app.run(debug=True)