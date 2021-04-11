# Fullstack citation application

*This documentation is similar if you read it from the API GitHub repository or from website GitHub repository*

## Objective 

This application implements CRUD operations for citations.

## Parts of the project

A No-SQL database.
A REST API [here](https://github.com/Alexandrp2/Project_Citations_PythonFlaskAPI).
A website (a client consuming the API) [here](https://github.com/Alexandrp2/Project_Citations_WebSite).

## Technologies

The database is based on **MongoDB**.
The REST API is based on Python **Flask**.
The website is based on **HTML/CSS/Javascript**.

## Pre-requisites

Nothing is required: this app can be runned without nothing installed ! 
How is it possible ? 
* The MongoDB database, the same collection as we create below is stored in the cloud (Mongo Atlas), 
* The Flask server is hosted in Microsoft Azure cloud
* The website has been developed to be used with no other action than launching the `index.html` file (no package, no dependencies to install)

We will see all the installation variants. For a full installation (called the *developer mode*) on your machine the requirements are : 
* Database: having installed mongodb. A GUI for MongoDB can be useful (we used Robo 3T).
* API : according the official documentation *Flask supports Python 3.5 and newer, Python 2.7* but it is recommended to use the latest Python version.


## Installation steps

### Developer mode

**Note: By default all the file in the API and the website are written to match the *developer mode*.**

1. Download the GitHub repositories
 * REST API [here](https://github.com/Alexandrp2/Project_Citations_PythonFlaskAPI).
 * Website [here](https://github.com/Alexandrp2/Project_Citations_WebSite).
2. Open mongodb and create a database named `citations-app` and one collection named `citations`
3. In this collection insert a dataset: copy/paste [this content](https://github.com/Alexandrp2/Project_Citations_PythonFlaskAPI/blob/master/mongoInitCollection) in the `citations` collection
    * This should create 14 documents in the collection
    * Your database is now set up
4. To set up your Flask environment, run these commands (on Windows). You can also consult the installation doc [here](https://flask.palletsprojects.com/en/1.1.x/installation/#installation).
    * This should be sufficient to work (although we don't create a virtual environment as recommended):
       * Install Flask : ```pip install flask```
       * Install pymongo: ```pip install flask_pymongo```
       * To manage CORS policy: ```pip install -U flask-cors```
       * **Optional** : To connect to a cluster (useful to connect to a mongoDB cloud) : ```pip install dnspython```
    * Your API is now ready for use
5. Run the 3 stacks :
    * Mongodb: start MongoDB
    * API (example with *Visual Studio Code*) : open the code editor, install a Python extension: `ms-python.python` and simply run it with the run command of the editor
    * Website : simply click on the `index.html` to open the project in a browser

Alternatively you can launch the Flask API by opening a Windows terminal where is located `flask_api_mongo_citations.py`, and then enter the 2 following commands.
More details in the Flask [Quickstart](https://flask.palletsprojects.com/en/1.1.x/quickstart/). 
```PowerShell
set FLASK_APP=flask_api_mongo_citations.py
flask run
```

### Variant for the MongoDB database (only)

Step 2 and 3 of the *Developer mode* can be skipped because the database and collection created during these steps are hosted in the cloud. 
In step 5 also skip *start MongoDB*.
Of course the content of the database depends on users actions and its content is not guarantee => **Important** : read below *Instructions of use*.

First notice that in this case installing ```pip install dnspython``` is mandatory (step 4 of the *Developer mode*) to connect the online cluster.

Change to make : in `app.py` of the API, follow instructions in the file (in the first lines of the file): 

```Python
'''
    Local database config.
    Comment of the following line if you use the distant MongoDB database (hosted in Mongo Atlas)
'''
app.config['MONGO_URI'] = "mongodb://localhost:27017/citations-app"

'''
    Distant database config.
    Remove the comment of the following line if you use the distant Flask API (hosted in Azure)
'''
# app.config['MONGO_URI'] = "mongodb+srv://citationDbUser:citationDbPassword@cluster0.ooo2r.mongodb.net/citations-app?retryWrites=true&w=majority"
```

Now, your Flask API request the distant database.

### Variant for the Flask API + MongoDB Database (full remote mode)

The steps 2 and 3 can be skipped (as mentionned above in *Variant for the MongoDB database (only)*).
Besides, here, step 1 (*Download the GitHub API repository*) and step 4 of the *Developer mode* can also be skipped.
In step 5 also skip the launch of API.

Change to make : in `scriptIndex.js`, `scriptMonespace.js` and `scriptStatistiques.js` (located in the directory `js` of the website), 
follow instructions in the beginning lines of these files:

```Javascript
/*
 * Comment of the following line if you use the distant Flask API (hosted in Azure)
 */
const _URL = 'http://localhost:5000/';

/*
 * Remove the comment of the following line if you use the distant Flask API (hosted in Azure)
 */
// const _URL = 'https://apicitations.azurewebsites.net/';
```
Now, your Website calls the distant Flask API, which one is coded to request the distant database.

Notice that it may have a **latency time of several seconds** before the server response, at least each time you first launch (*awake*) the website.
Consider it as normal.


## Instructions of use

Just consider that you can connect "Mon Espace" with any login 
and that the collection already contains logins : alice, alexis, armand, amandine, ambre, artur.

If you test with a locally created collection, feel free to experiment as you want.

If testing with the distant database (in the mongo cloud), it is asked you maintain the initial state of the 14 documents.
Indeed this is not a production app, rather an experimental app and **we wish a similar experience over time for all users** that try it.

To maintain a minimum stable database content: 
* If you connect as "alice", avoid CREATE, UPDATE and DELETE operations.
* To execute these operations, prefer log in as a not exiting login and do all CRUD operations you want.