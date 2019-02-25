# SETBOOKS-PYTHON-FLASK-API
A simple Set books RESTFul API in Flask With JSON Web Token Authentication and Flask-SQLAlchemy -
To access this api end points an auth token is requierd.
To generate an auth token the login method is called : #method used to generate an auth token.user passes in user name and thier password.once authenticated, an access token is generated. The token expires after 30 minutes. The token must be passed in every api call.

API end points:
user:
    supports get request : #method gets all user.action limted to admin users

    supports get request : #method gets one user whose public id is supplied. action limted to admin users

    supports post request : #method createds new users.action limted to admin users

    supports put request :  #method used to promote a user to an admin level, whose public id is supplied.action limted to admin users

    supports delete request : #method used to delete a user, whose public id is passed.action limted to admin users


 language:

    supports get request : #method used to get all languages.can be performed by any user

    supports get request : #method used to get one language when language id is passed.can be performed by any user

    supports post request : #methods used to create languages.action limted to admin users

    supports delete request : #method used to delete a language.action limted to admin users

setbooks:
 
    supports get request : #this method gets all  set books beloging to a language, language id is passed

    supports get request : #this method gets one set book when set book id is passed

    supports post request : #method used to create new setbook.action limted to admin users

    supports delete request : #method used to delete a setbook.action limted to admin users






