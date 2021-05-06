from flask import Flask, request, Response, jsonify, json, session
from flask_session import Session
from flask_pymongo import PyMongo, MongoClient
from flask_cors import CORS
from bson.json_util import dumps
from bson import ObjectId
from argon2 import PasswordHasher, exceptions
from datetime import timedelta, datetime
import base64, binascii

class SessionManager:
    
    def __init__(self, mongoClient):
        self.mongo = mongoClient
        

    def isExpiredSession(self, sessionId):
        session = self.mongo.db.sessions.count_documents({"id":{"$regex": sessionId +'.*', "$options" :'i'},"expiration": {'$gt': datetime.now()}})
        # print("Nombre de session trouvées ", session)
        if session == 0:
            self.clearAllExpiredSessions()
            return True
        else :
            return False
  
  
    def base64_to_string_converter(self, authorizationHeader):
        # The header is of form "Basic the_base_64_message"
        sessionIdBase64 = authorizationHeader[5:len(authorizationHeader)]
        base64_bytes = sessionIdBase64.encode('ascii')
        sessionId_bytes = base64.b64decode(base64_bytes)
        sessionId = sessionId_bytes.decode('ascii')
        return sessionId


    def isAuthorized(self, authorizationHeader): 
        
        if ( authorizationHeader != None ) :
            # Check session validity
            sessionId = self.base64_to_string_converter(authorizationHeader)
            expiredSession = self.isExpiredSession(sessionId)
            if ( not expiredSession ) :
                return True
            else :
                return False
        
        else :
            return False


    def authorizedResponse(self, authorizationHeader, status20xResponse):
        
        failedAuthResponse = json.dumps({"Detail": "Unauthorized - Not found valid session to access the ressource"})
        httpResponseHeaderOptions = {
            'X-Frame-Options': 'sameorigin', 
            'X-Content-Type-Options': 'nosniff'
        }

        if ( authorizationHeader != None ) :
            # Check session validity
            sessionId = self.base64_to_string_converter(authorizationHeader)
            expiredSession = self.isExpiredSession(sessionId)

            if ( not expiredSession ) :
                return Response(status20xResponse,
                                headers = httpResponseHeaderOptions,
                                status=200,
                                mimetype='application/json')
            else :
                return Response(failedAuthResponse,
                                headers = httpResponseHeaderOptions,
                                status=401,
                                mimetype='application/json')
        
        else :
            return Response(failedAuthResponse,
                            headers = httpResponseHeaderOptions,
                            status=401,
                            mimetype='application/json')

    def clearAllExpiredSessions(self):
        self.mongo.db.sessions.delete_many({"expiration": {'$lt': datetime.now()}})