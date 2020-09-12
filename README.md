1.The application must expose an endpoint where users can login using username + password, which provides <br>
  a JWT Token or any other form of authentication.<br>
2.The rest of the exposed endpoints must be secured and must validate the token (will be sent in the <br>
  Authorization header)<br>
3.The application must have the following functionalities: create users (and assign to an existing <br>
  organization), list users,update users,modify users. Same functionalities for organizations.<br>
4.The relation between users and organizations is: an organization can have multiple users, a user belongs<br>
  to an organization.<br>
5.When retrieving the list of users, the users password must not be returned<br>
6.No frontend/GUI is required<br>
  Project can be uploaded to Github, but not required<br>
  Can use: postman/soapui for testing REST API, but not required<br>
7.Technologies to be used:<br>
  Python 3.X<br>
  Flask<br>
  SQLAlchemy<br>
  Any of the following db: postgresql/sqlserver/mysql (in order of preferences)<br>
  
User comments:<br>
required : mysql server run<br> 
to be installed : flask,flask-sqlalchemy,flask-mysql,pyjwt,sqlalchemy-utils 
