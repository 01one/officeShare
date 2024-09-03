Change the necessary data when deploying in a real-world application. 
Update the password, cookie secret, and if using PostgreSQL with the (Docker Compose), you can Edit the Docker Compose password and username to configture the database.

You can test this application on Render, especially with the SQLite version. 
However, for long-term data storage, use PostgreSQL.




Currenly Debug Mode is on For testing
You can turn off the debug mode by 
editing end  the app.py in the 
	app = Application([
  #app content
	], debug=True, **settings)

Make the debug mode false

debug=False
