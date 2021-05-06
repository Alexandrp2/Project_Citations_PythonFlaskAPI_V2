from flask import Flask, request, Response, jsonify, json, session
from flask_session import Session
from flask_pymongo import PyMongo, MongoClient
from flask_cors import CORS
import smtplib, email.mime.multipart, email.mime.text
from bson.json_util import dumps
from bson import ObjectId
from argon2 import PasswordHasher, exceptions
from datetime import timedelta, datetime
import uuid
import base64, binascii
from sessionManager import SessionManager
from mailManager import MailManager


app = Flask(__name__)

# Allowing CORS for the whole application (all routes) => CORS(app)
# Security concern : only allow requests from this origin (allow requests only if coming from the website)
CORS(app, origins='http://localhost:63342/*')

'''
    Local database config.
    Comment of the following line if you use the distant MongoDB database (hosted in Mongo Atlas)
'''
app.config['MONGO_URI'] = "mongodb://localhost:27017/citations-app2"
mongoClient = MongoClient(host='mongodb://localhost:27017/')


'''
    Distant database config.
    Remove the comment of the following line if you use the distant Flask API (hosted in Azure)
'''
# app.config['MONGO_URI'] = "mongodb+srv://citationDbUser:citationDbPassword@cluster0.ooo2r.mongodb.net/citations-app2?retryWrites=true&w=majority"
# mongoClient = MongoClient(host='mongodb+srv://citationDbUser:citationDbPassword@cluster0.ooo2r.mongodb.net/citations-app2?retryWrites=true&w=majority')

mongo = PyMongo(app)


'''
A secret key that will be used for securely signing the session cookie
and can be used for any other security related needs by extensions or your application
'''
app.config['SECRET_KEY'] = 'dkT2664ssT'

# Session config
app.config['SESSION_TYPE'] = 'mongodb'
app.config['SESSION_MONGODB'] = mongoClient
app.config['SESSION_MONGODB_DB'] = "citations-app2"
app.config['SESSION_MONGODB_COLLECT'] = "sessions"
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_PERMANENT'] = True
# For a 1 minute validity session, set minutes=121 (date is not the same format before database & this API)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=122)
# if SESSION_USE_SIGNER set to True, you have to set flask.Flask.secret_key
app.config['SESSION_USE_SIGNER'] = True 

Session(app)

sessMgr = SessionManager(mongo)
mailMgr = MailManager()
ph = PasswordHasher()

''' HEADERS
X-Frame-Options : 
    éviter les attaques de clickjacking pour s'assurer que le contenu ne soit pas embarqué dans d'autres sites
X-Content-Type-Options 
    est un marqueur utilisé par le serveur pour indiquer que les types MIME annoncés dans les en-têtes Content-Type ne doivent pas être modifiés ou et suivis  
'''
httpResponseHeaderOptions = {
    'X-Frame-Options': 'sameorigin', 
    'X-Content-Type-Options': 'nosniff'
}

@app.route('/', methods=['GET', 'POST'])
def test():
    return Response(response=json.dumps({"Status": "UP"}),
                    status=200,
                    headers = httpResponseHeaderOptions,
                    mimetype='application/json')


'''

ROUTES CITATIONS


'''

@app.route('/citations', methods=['GET'])
def getAllCitations():
    
    citations = mongo.db.citations.find({}, {'likers': 0, 'citationPoster': 0})
    response = dumps(citations)

    if 'Authorization' in request.headers:
        authorizationHeader = request.headers['Authorization']
        authorizedResponse = sessMgr.authorizedResponse(authorizationHeader, response)
        return authorizedResponse
    
    else :
        return Response(response,   
                        status=200,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')


@app.route('/citation/id/<id>', methods=['GET'])
def getCitationById(id):
    citation = mongo.db.citations.find_one({'_id':ObjectId(id)})
    response = dumps(citation)
    return Response(response,
                    status=200,
                    headers = httpResponseHeaderOptions,
                    mimetype='application/json')


@app.route('/citations/recherche/auteur', methods=['POST'])
def getCitationsByAuthor():
    requestBoby = request.get_json()
    authorToSearch = requestBoby.get('authorToSearch')
    citations = mongo.db.citations.find(
        {"author":{"$regex": authorToSearch +'.*', "$options" :'i'}},
        {'likers': 0, 'citationPoster': 0})
    
    response = dumps(citations)
    
    if len(citations.distinct("_id")) == 0 :
        return Response(response,
                        status=204,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')
    else:
        return Response(response,
                        status=200,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')

@app.route('/citations/recherche/string', methods=['POST'])
def getCitationsByCitation():
    requestBoby = request.get_json()
    stringToSearch = requestBoby.get('stringToSearch')
    citations = mongo.db.citations.find(
        {"citation":{"$regex": stringToSearch +'.*', "$options" :'i'}},
        {'likers': 0, 'citationPoster': 0})
   
    response = dumps(citations)

    if len(citations.distinct("_id")) == 0:
        return Response(response,
                        status=204,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')
    else:
        return Response(response,
                        status=200,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')

@app.route('/citations/recherche/auteuretstring', methods=['POST'])
def getCitationsByAuthorAndString():
    requestBoby = request.get_json()
    authorToSearch = requestBoby.get('authorToSearch')
    stringToSearch = requestBoby.get('stringToSearch')
    citations = mongo.db.citations.find(
        {"author":{"$regex": authorToSearch +'.*', "$options" :'i'}, 
        "citation":{"$regex": stringToSearch +'.*', "$options" :'i'}},
        {'likers': 0, 'citationPoster': 0})
    
    response = dumps(citations)
    
    if len(citations.distinct("_id")) == 0 :
        return Response(response,
                        status=204,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')
    else:
        return Response(response,
                        status=200,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')


'''

ROUTES MON ESPACE

'''


@app.route('/login', methods=['POST'])
def getUser():
    requestBoby = request.get_json()   
    loginInput = requestBoby.get('login')

    findSameUserLogin = mongo.db.users.count_documents({"login": loginInput})
    user = mongo.db.users.find({'login': loginInput})

    # user found
    if ( findSameUserLogin == 1) and (loginInput == user[0]['login'] ) :
        passwordInput = requestBoby.get('pwd')
        passwordCorrect = user[0]['password']
        
        # Password matching
        try:
            checkPassword = ph.verify(passwordCorrect, passwordInput)
            session[loginInput] = loginInput
            #print("Une session s'ouvre pour ", loginInput, "(len=", len(loginInput), ")et vaut : ", session.get(loginInput))
            #print("session id = ", session.sid)
            response = json.dumps({"Detail": "Accepted - Matching login/password", "sid" : session.sid})
            return Response(response,
                            status=202,
                            headers = httpResponseHeaderOptions,
                            mimetype='application/json')
        
        # Password not matching
        except exceptions.VerifyMismatchError:
            response = json.dumps({"Detail": "Forbidden - Not matching login/password"})
            return Response(response,
                            status=403,
                            headers = httpResponseHeaderOptions,
                            mimetype='application/json')
    

    # user not found
    else :
        response = json.dumps({"Detail": "Not Found - Not existing user"})
        return Response(response,
                        status=404,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')


@app.route('/register', methods=['POST'])
def postUser():
    requestBoby = request.get_json()
    login = requestBoby.get('login')
    mail = requestBoby.get('mail')

    # We require only the pseudo to be unique, not the mail    
    findSameUserLogin = mongo.db.users.count_documents({"login": login})
    
    # Not already existing login
    if findSameUserLogin == 0:
        password = ph.hash(requestBoby.get('pwd'))
        insertUser = mongo.db.users.insert_one({
                "login": login,
                "password": password,
                "mail": mail,
                "role": 5
            })
    
        session[login] = login
        print("session id = ", session.sid, " est de type", type(session.sid))

        response = json.dumps({"Detail": "Created - User was inserted in database", "sid" : session.sid})
        return Response(response,
                        status=201,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')

    # Already existing login
    else :
        response = json.dumps({"Detail": "Forbidden - Already existing user login"})
        return Response(response,
                        status=403,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')


@app.route('/logout', methods=['POST'])
def endSession():
    if 'Authorization' in request.headers:
        authorization = request.headers['Authorization']
        
        if ( authorization != None ) :
            sessionId = sessMgr.base64_to_string_converter(authorization)    
            expiredSession = sessMgr.isExpiredSession(sessionId)
            mongo.db.sessions.delete_many({"id": {"$regex": sessionId +'.*', "$options" :'i'}})
            sessMgr.clearAllExpiredSessions()

            response = json.dumps({"Detail": "Session removed succesfully"})
            return Response(response,
                            status=200,
                            headers = httpResponseHeaderOptions,
                            mimetype='application/json')



@app.route('/authorization', methods=['GET'])
def isAuthorized(): 
    
    response = json.dumps({"Authorization": "authorized"})

    if 'Authorization' in request.headers :
        authorizationHeader = request.headers['Authorization']
        authorizedResponse = sessMgr.authorizedResponse(authorizationHeader, response)
        return authorizedResponse
    
    else :
        return Response(response,
                        status=401,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')



@app.route('/citation/favoris/mesCitations', methods=['POST'])
def MesCitationFavByIPoster():
    
    requestBoby = request.get_json()
    poster = requestBoby.get('Poster')
    citation = mongo.db.citations.find({'likers.login':poster})
    response = dumps(citation)

    if 'Authorization' in request.headers:
        authorizationHeader = request.headers['Authorization']
        authorizedResponse = sessMgr.authorizedResponse(authorizationHeader, response)
        return authorizedResponse
    
    else :
        response = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
        return Response(response,
                        status=401,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')


@app.route('/citation/post/mesCitations', methods=['POST'])
def MesCitationPostByIPoster():
    requestBoby = request.get_json()
    poster = requestBoby.get('Poster')
    citation = mongo.db.citations.find({'citationPoster':poster})
    response = dumps(citation)
    
    if 'Authorization' in request.headers:
        authorizationHeader = request.headers['Authorization']
        authorizedResponse = sessMgr.authorizedResponse(authorizationHeader, response)
        return authorizedResponse
    
    else :
        response = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
        return Response(response,
                        status=401,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')


@app.route('/citation/delete/macitation', methods=['POST'])
def deleteCitationByIdAndPoster():
    requestBoby = request.get_json()
    citationId = ObjectId(requestBoby.get('citationId'))
    poster = requestBoby.get('Poster')
    
    if 'Authorization' in request.headers:
        authorizationHeader = request.headers['Authorization']
        authorized = sessMgr.isAuthorized(authorizationHeader)

        if ( authorized ) :
            mongo.db.citations.delete_many({"_id": citationId,"citationPoster":poster})
            return Response(status=200,
                            headers = httpResponseHeaderOptions,
                            mimetype='application/json')
        
        else :
            response = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
            return Response(response,
                        status=401,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')
        
    else :
        response = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
        return Response(response,
                        status=401,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')


@app.route('/citation/favoris/add', methods=['POST'])
def addCitationByIdAndPosterToFav():
    requestBoby = request.get_json()
    citationId = ObjectId(requestBoby.get('citationId'))
    poster = requestBoby.get('Poster')

    if 'Authorization' in request.headers:
        authorizationHeader = request.headers['Authorization']
        authorized = sessMgr.isAuthorized(authorizationHeader)

        if ( authorized ) :
            citation = mongo.db.citations.update(
                { '_id': citationId}, {'$inc': {"savedInFavorites": 1, }, '$addToSet':  {'likers' :{'name': poster,'login': poster }, } })
            response = dumps(citation)
            return Response(response,
                            status=200,
                            headers = httpResponseHeaderOptions,
                            mimetype='application/json')
        else :
            response = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
            return Response(response,
                        status=401,
                        mimetype='application/json')
    else :
        response = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
        return Response(response,
                        status=401,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')


@app.route('/citation/favoris/del', methods=['POST'])
def deleteCitationByIdAndPosterToFav():
    requestBoby = request.get_json()
    citationId = ObjectId(requestBoby.get('citationId'))
    poster = requestBoby.get('Poster')
    
    if 'Authorization' in request.headers:
        authorizationHeader = request.headers['Authorization']
        authorized = sessMgr.isAuthorized(authorizationHeader)

        if ( authorized ) :
            citation = mongo.db.citations.update(
                { '_id': citationId},  {'$inc':  {   "savedInFavorites": -1,  }, '$pull':  {'likers' :{'login':poster }, } })
            response = dumps(citation)
            return Response(response,
                            status=200,
                            headers = httpResponseHeaderOptions,
                            mimetype='application/json')
        else :
            response = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
            return Response(response,
                        status=401,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')
    else :
        response = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
        return Response(response,
                        status=401,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')


@app.route('/citation/ajouter', methods=['POST'])
def createNewCitation():
    requestBoby = request.get_json()
    
    author = requestBoby.get('author')
    year = requestBoby.get('year')
    nationality = requestBoby.get('nationality')
    citation = requestBoby.get('citation')
    poster = requestBoby.get('Poster')

    if 'Authorization' in request.headers:
        authorizationHeader = request.headers['Authorization']
        authorized = sessMgr.isAuthorized(authorizationHeader)

        if ( authorized ) :
            citation = mongo.db.citations.insert({
                "author": author,
                "citation": citation,
                "year": year,
                "nationality": nationality,
                "savedInFavorites": 0,
                "citationPoster" : poster,
                "likers":[]
            })
            response = dumps(citation)
            return Response(response,
                            status=200,
                            headers = httpResponseHeaderOptions,
                            mimetype='application/json')
        else :
            response = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
            return Response(response,
                        status=401,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')
    else :
        response = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
        return Response(response,
                        status=401,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')


@app.route('/resetpassword', methods=['POST'])
def resetpassword():
    requestBoby = request.get_json()
    pseudo = requestBoby.get('login')
    mailUser = requestBoby.get('mailUser')

    findMatchingPseudoAndMail = mongo.db.users.count_documents({"login": pseudo, "mail": mailUser})
    
    if findMatchingPseudoAndMail == 1 :
        newPwdUuid = str(uuid.uuid4())
        response = mailMgr.sendMsg(pseudo, mailUser, newPwdUuid)
        
        newPwdUuidHashed = ph.hash(newPwdUuid)
        updatedUser = mongo.db.users.update_one(
            {'login': pseudo}, 
            {"$set":
                {"password": newPwdUuidHashed}
            }
        )

        return response
    
    else :
        response = json.dumps({"Detail": "Not Found - No matching found with these pseudo and mail"})
        return Response(response,
                        status=204,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')
    

@app.route('/updatepassword', methods=['POST'])
def updatepassword():
    requestBoby = request.get_json()
    login = requestBoby.get('login')
    mailUser = requestBoby.get('mailUser')
    currentPwd = requestBoby.get('currentPwd')
    newPwd = requestBoby.get('newPwd')

    # Login and pseudo matching
    findMatchingPseudoAndMail = mongo.db.users.count_documents({"login": login, "mail": mailUser})

    user = mongo.db.users.find({'login': login, "mail": mailUser})

    # user found
    if ( findMatchingPseudoAndMail == 1) and (login == user[0]['login'] ) :
        passwordCorrect = user[0]['password']
        
        # Password matching
        try:
            checkPassword = ph.verify(passwordCorrect, currentPwd)
            newPwdHashed = ph.hash(newPwd)
            updatedUser = mongo.db.users.update_one(
                {'login': login}, 
                {"$set":
                    {"password": newPwdHashed}
                }
            )
            response = json.dumps({"Detail": "Updated"})
            return Response(response,
                            status=200,
                            headers = httpResponseHeaderOptions,
                            mimetype='application/json')
        
        # Password not matching
        except exceptions.VerifyMismatchError:
            response = json.dumps({"Detail": "Forbidden - Not matching login/password"})
            return Response(response,
                            status=403,
                            headers = httpResponseHeaderOptions,
                            mimetype='application/json')
    

    # user not found
    else :
        response = json.dumps({"Detail": "Not Found - Not existing user"})
        return Response(response,
                        status=404,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')

'''

ROUTES STATISTIQUES

'''

@app.route('/citation/stats/<stat>', methods=['GET'])
def statCitations(stat):
    
    authorized = False

    if 'Authorization' in request.headers:
        authorizationHeader = request.headers['Authorization']
        authorized = sessMgr.isAuthorized(authorizationHeader)

    if authorized :
        
        if stat == 'top3citation':
            citation = mongo.db.citations.find({}, { 'savedInFavorites': 1, 'citation': 1, 'author': 1 }).sort([( 'savedInFavorites', -1 )]).limit(3)

        elif stat =='bestlogin':
            citation = mongo.db.citations.aggregate( [ { '$unwind': "$citationPoster" }, { '$sortByCount': "$citationPoster" },{ '$sort': {"count": -1 }}, { '$limit': 1 }   ])


        elif stat =='topquotedauthor':
            citation = mongo.db.citations.aggregate( [ 
                { '$match': { '$and': [ { 'author': {'$ne': None } }, { 'author': {'$ne': "" } }, { 'author' : { '$exists': True } } ] } },
                { '$sortByCount': "$author" },
                { '$limit': 1 }   
            ])


        elif stat =='favouriteauthor':
            citation = mongo.db.citations.aggregate( [
                { '$project':{   'author': 1, 'numberOfLikers': { '$size': "$likers" }  } },   
                { '$match': { '$and': [ { 'author': {'$ne': None } }, { 'author': {'$ne': "" } }, { 'author' : { '$exists': True } } ] } },
                { '$group' :   {   "_id" : "$author",  "nbLikers": {'$sum': "$numberOfLikers"}   }  },
                { '$sort': {"nbLikers": -1 }},
                { '$limit': 1 }  
                ] 
            )


        elif stat== 'anonymCitations':
            citation = mongo.db.citations.aggregate(
                [
                    { '$match': { '$or': [ { 'author': {'$eq': None } }, { 'author': {'$eq': "" } }, { 'author' : { '$exists': False } } ] } }, 
                    { '$count' : "nbCitationSansAuteur" } 
                ]
            )
            

        response = dumps(citation)
        return Response(response,
                        status=200,
                        headers = httpResponseHeaderOptions,
                        mimetype='application/json')
    
    else :
        failedAuthResponse = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
        return Response(failedAuthResponse,
                            status=401,
                            headers = httpResponseHeaderOptions,
                            mimetype='application/json')


if __name__ == "__main__":
    app.run(debug=True)