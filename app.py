# required : mysql server run 
# to be installed : flask,flask-sqlalchemy,flask-mysql,pyjwt,sqlalchemy-utils 
from flask import Flask,request,jsonify,make_response 
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash,check_password_hash   
from datetime import datetime,timedelta 
from functools import wraps 
from sqlalchemy.sql import func
# public id and json web token
import uuid,jwt,sqlalchemy_utils

# database configuration (one database with 2 tables)
db_name='user';db_dialect='mysql';db_driver='pymysql';db_user='root';db_passw='1234';\
db_host='localhost';db_port='3306';user_table='user_table';organization_table='organization_table'
user_engine='{0}+{1}://{2}:{3}@{4}:{5}/{6}'.format(db_dialect,db_driver,db_user,db_passw,db_host,db_port,db_name)
app = Flask(__name__)
# app configuration 
app.config['SECRET_KEY']='write a key here'
app.config['SQLALCHEMY_DATABASE_URI']=user_engine
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=True
db=SQLAlchemy(app)

# Database ORMs 
class Organization(db.Model):
      __tablename__= organization_table
      __mapper_args__ = { 'confirm_deleted_rows': False}
      id = db.Column(db.Integer, primary_key=True)
      name = db.Column(db.String(100), unique = True)
      city = db.Column(db.String(100))
      cui =  db.Column(db.String(70), unique = True)	  

class User(db.Model): 
      __tablename__ = user_table
      id = db.Column(db.Integer, primary_key = True) 
      public_id = db.Column(db.String(50), unique = True) 
      name = db.Column(db.String(100))         
      email = db.Column(db.String(70), unique = True) 
      password = db.Column(db.Text(), nullable=False) 
      owner_id=db.Column(db.Integer)
      	 
# create database if not exist
def create_database(db):
    if not sqlalchemy_utils.database_exists(db):sqlalchemy_utils.create_database(db)

# add transaction    
def add(object):
    db.session.add(object)
    db.session.commit() 
    
# delete transaction       
def delete(object):
    db.session.delete(object)
    db.session.commit()

# check if a form field is empty or not    
def check_empty_field(object=str()):
    # not empty field
    if object not in ['',' '*len(object)]:
       return 1
    # empty field
    else: return 0    
        
# verify JWT token
def token_required(f): 
    @wraps(f) 
    def decorated(*args, **kwargs): 
        token = None
        # jwt is in request header 
        if 'x-access-token' in request.headers:token = request.headers['x-access-token'] 
        # if token is not passed return 401
        if not token:return jsonify({'message' : 'Token is missing !!'}), 401
        try: 
            # decode the payload to find stored details 
            data = jwt.decode(token, app.config['SECRET_KEY']) 
            current_user = User.query.filter_by(public_id = data['public_id']).first() 
        except: return jsonify({ 'message' : 'Token is invalid !!'}), 401
        # current logged user contex to the routes 
        return f(current_user, *args, **kwargs) 
    return decorated 

# register user route 
@app.route('/signup', methods =['POST']) 
def signup(): 
    # datas from form
    data=request.form
    name,email,password,organization = data.get('name'),data.get('email'),data.get('password'),data.get('organization')
    # when sign in do not allow empty fields
    if not name or not password or not email:
       return make_response('Emty fields !',401,{'WWW-Authenticate':'Basic realm ="Field required !"'})  
    else:    
        # if user name or user email do not exist populate user database
        if (User.query.filter_by(name=name).first() is None) and (User.query.filter_by(email=email).first() is None):
           # empty organization field is not allowed
           if not organization:
              return make_response('No organization !',401,{'WWW-Authenticate':'Basic realm ="Organization required !"'}) 
           else:
                # if organization do not exist in database insert in database
                if Organization.query.filter_by(name=organization).first() is None:  
                   org=Organization(name=organization,city=None)  
                   add(org)
                   # find latest id from organization_table
                   org_query_id= db.session.query(func.max(Organization.id)).scalar()
                else:
                     # if organization exist take Organization id to insert in User
                     org_query_id=Organization.query.filter_by(name=organization).first().id              	    	 
           # create user object (instantiate User class)
           user=User(public_id=str(uuid.uuid4()),name=name,email=email,password=generate_password_hash(password),owner_id=org_query_id) 
           # populate user database
           add(user)
           return make_response(' : '.join(('Successfully register',name)), 201) 
        else: 
             # if user name or user email exists return 202
             if (User.query.filter_by(name=name).first() is not None):
                return make_response('Name: {} already taken ! Choose other name ! '.format(name), 202)
             elif (User.query.filter_by(email=email).first()  is not None):
                  return make_response('Email: {} already taken ! Please log in ! '.format(email), 202)

# route loging user  
@app.route('/login', methods =['POST']) 
def login(): 
    # dictionary with datas form
    auth = request.form 
    if not auth or not auth.get('name') or not auth.get('password'):     
       # if name or/and password are missing return 401
       return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm ="Login required !"'}) 
    user=User.query.filter_by(name=auth.get('name')).first()  
    if not user: 
       # if user not exist return 401
       return make_response('Could not verify',401,{'WWW-Authenticate' : 'Basic realm ="User does not exist !"'}) 
    # check hashed password stored in user database
    if check_password_hash(user.password,auth.get('password')): 	
       # generates the JWT Token 
       token=jwt.encode({'public_id':user.public_id,'exp':datetime.utcnow()+timedelta(minutes=30)},app.config['SECRET_KEY'])
       return make_response(jsonify({'token' : token.decode('UTF-8')}), 201) 
    # if password do not match return 403
    return make_response('Wrong password !',403,{'WWW-Authenticate' : 'Basic realm ="Wrong Password !"'}) 		 

# route /get_users gave list of users
@app.route('/get_users', methods =['GET']) 
@token_required
def get_users(current_user): 
    # query datas from database  
    users = User.query.all() 
    # converting the query objects to list of jsons 
    output = [] 
    for user in users: 
        # appending the user data json to the response list
        org=Organization.query.filter_by(id = user.owner_id).first() 
        output.append({'public_id':user.public_id,'name':user.name,'email':user.email,'organization':org.name})
    return jsonify({'users': output}) 

# list of organizations
@app.route('/get_organizations', methods =['GET']) 
@token_required
def get_organizations(current_user): 
    # query datas from database  
    organizations = Organization.query.all() 
    # converting the query objects to list of jsons 
    output = [] 
    for organization in organizations: 
        # appending the organization data json to the response list
        output.append({'name':organization.name,'city':organization.city,'cui':organization.cui})
    return jsonify({'organizations': output})

# modify organizations
@app.route('/update_organization', methods =['POST']) 
@token_required
def mod_organization(current_user):
    data=request.form 
    #print ('data=',data.to_dict())
    # form datas
    name,city,cui = data.get('name'),data.get('city'),data.get('cui')
    # what we have in database
    current_org_id=current_user.owner_id
    org=Organization.query.filter_by(id=current_org_id).first()
    current_org_name=org.name
    current_org_cui=org.cui
    current_org_city=org.city
    # if form fields are not empty
    #if name is not None and city is not None and cui is not None:  
    if check_empty_field(name)==1 and check_empty_field(city)==1 and check_empty_field(cui)==1 :     
       # if modify organization name
       if name != current_org_name:
          # if modified organization name is not in database
          if Organization.query.filter_by(name=name).first() is None:
             org.name=name 
             db.session.commit()
          # if modified organization name is in database we will modify owner_id from user_table
          else: 
               # find id belongs to modified organization name
               org1=Organization.query.filter_by(name=name).first() 
               org1_id=org1.id
               current_user.owner_id=org1_id
               db.session.commit()
       # if modify organization cui
       if cui != current_org_cui: 
          # if modified cui is not in database 
          if Organization.query.filter_by(cui=cui).first() is None:                    
             org.cui=cui
             db.session.commit()
          # if modified cui is in database  
          else: return make_response('Organization CUI : {} already in use ! You can not change organization CUI is unique ! '.format(cui), 202)      
       # if modify city
       if city != current_org_city:
          org.city=city
          db.session.commit()
       elif city == current_org_city:
            pass     
       return jsonify({'update result': data})  
    return make_response('Empty fields!', 202)         

@app.route('/update_user', methods =['POST']) 
@token_required
def mod_user(current_user):
    data=request.form 
    # what we have in form
    name,email,password = data.get('name'),data.get('email'),data.get('password')
    # what we have in database
    usr=User.query.filter_by(id=current_user.id).first()
    #if name is not None and email is not None or password is not None :
    if check_empty_field(name)==1 and check_empty_field(email)==1 and check_empty_field(password)==1 :     
       # if modify user name
       if name != current_user.name: 
          # if modified user name is not in database
          if User.query.filter_by(name=name).first() is None:
             usr.name=name 
             db.session.commit()
          # if modified user name is in database update not allowed
          else:return make_response('Name : {} already in use ! You can not change name ! '.format(name), 202)
       # if modify user email
       if email != current_user.email:
          # if modified user email is not in database
          if User.query.filter_by(email=email).first() is None:        
             usr.email=email
             db.session.commit()
          # if modified user email is in database update not allowed   
          else:return make_response('Email : {} already in use ! You can not change email ! '.format(email), 202)
       # if modify user password
       if password != current_user.password:
          usr.password=generate_password_hash(password)  
          db.session.commit()
       elif password == current_user.password:
            pass
       return jsonify({'update result': data})     
    return make_response('Empty field !', 202)    

# when delete organization we need to delete all users
# that belongs to deleted organization   				
@app.route('/delete_organization', methods =['POST']) 
@token_required
def del_organization(current_user):    
    delete_org = request.form 
    org_name = delete_org.get('name')
    #if org_name is not None:
    if check_empty_field(org_name)==1:    
       org = Organization.query.filter_by(name=org_name).first()
       user_name = User.query.filter_by(owner_id=org.id).all()
       # delete organization
       delete(org)
       # delete users with same organization
       for u in user_name:
           delete(u)  
       return jsonify({'delete organization': org_name})
    else:return make_response('Empty field !', 202)  

# when delete user if we have no owner_id in user_table that corespond 
# to organization id than we delete organization from organization_table  				
@app.route('/del_user', methods =['POST']) 
@token_required
def del_user(current_user):    
    delete_usr = request.form
    # field name in form 
    usr_name = delete_usr.get('name')
    #if usr_name is not None:
    if check_empty_field(usr_name)==1:    
       usr = User.query.filter_by(id=current_user.id).first()
       own_id = usr.owner_id
       org = Organization.query.filter_by(id=own_id).first()
       user_ids=User.query.filter_by(owner_id=own_id).all()
       if len(user_ids) == 1 :
          # delete user and organization 
          delete(org)
          delete(usr)
       elif len(user_ids) > 1 :
            # delete only user
            delete(usr)   
       return jsonify({'delete user': usr_name})
    else:return make_response('Empty field !', 202) 
    
if __name__ == "__main__":    
   create_database(user_engine)
   db.create_all()
   app.run(debug = True) 
