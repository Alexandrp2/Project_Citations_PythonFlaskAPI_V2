from flask import Flask, request, Response, jsonify, json
from flask_pymongo import PyMongo
from flask_cors import CORS
from bson.json_util import dumps
from bson import ObjectId
import re

'''
Pour la gestion du CORS
pip install -U flask-cors
'''

app = Flask(__name__)

# Allowing CORS for the whole application (all routes)
CORS(app)

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


mongo = PyMongo(app)

@app.route('/', methods=['GET'])
def test():
    return Response(response=json.dumps({"Status": "UP"}),
                    status=200,
                    mimetype='application/json')


'''

ROUTES CITATIONS

'''


@app.route('/citations', methods=['GET'])
def getAllCitations():
    citations = mongo.db.citations.find({})
    response = dumps(citations)
    return Response(response,
                    status=200,
                    mimetype='application/json')


@app.route('/citation/id/<id>', methods=['GET'])
def getCitationById(id):
    citation = mongo.db.citations.find_one({'_id':ObjectId(id)})
    response = dumps(citation)
    return Response(response,
                    status=200,
                    mimetype='application/json')


@app.route('/citations/recherche/auteur', methods=['POST'])
def getCitationsByAuthor():
    requestBoby = request.get_json()
    authorToSearch = requestBoby.get('authorToSearch')
    #autor = 'aU'
    citations = mongo.db.citations.find(
        {"author":{"$regex": authorToSearch +'.*', "$options" :'i'}})
    response = dumps(citations)
    return Response(response,
                    status=200,
                    mimetype='application/json')

@app.route('/citations/recherche/string', methods=['POST'])
def getCitationsByCitation():
    requestBoby = request.get_json()
    stringToSearch = requestBoby.get('stringToSearch')
    citations = mongo.db.citations.find(
        {"citation":{"$regex": stringToSearch +'.*', "$options" :'i'}})
    response = dumps(citations)
    return Response(response,
                    status=200,
                    mimetype='application/json')

@app.route('/citations/recherche/auteuretstring', methods=['POST'])
def getCitationsByAuthorAndString():
    requestBoby = request.get_json()
    authorToSearch = requestBoby.get('authorToSearch')
    stringToSearch = requestBoby.get('stringToSearch')
    citations = mongo.db.citations.find(
        {"author":{"$regex": authorToSearch +'.*', "$options" :'i'}, 
        "citation":{"$regex": stringToSearch +'.*', "$options" :'i'}})
    response = dumps(citations)
    return Response(response,
                    status=200,
                    mimetype='application/json')


'''

ROUTES MON ESPACE

'''

@app.route('/citation/favoris/mesCitations', methods=['POST'])
def MesCitationFavByIPoster():
    requestBoby = request.get_json()
    poster = requestBoby.get('Poster')
    citation = mongo.db.citations.find({'likers.login':poster})
    response = dumps(citation)
    return Response(response,
                    status=200,
                    mimetype='application/json')


@app.route('/citation/post/mesCitations', methods=['POST'])
def MesCitationPostByIPoster():
    requestBoby = request.get_json()
    poster = requestBoby.get('Poster')
    citation = mongo.db.citations.find({'citationPoster':poster})
    response = dumps(citation)
    return Response(response,
                    status=200,
                    mimetype='application/json')


@app.route('/citation/delete/macitation', methods=['DELETE'])
def deleteCitationByIdAndPoster():
    requestBoby = request.get_json()
    citationId = ObjectId(requestBoby.get('citationId'))
    poster = requestBoby.get('Poster')
    citation = mongo.db.citations.remove({"_id": citationId,"citationPoster":poster})
    response = dumps(citation)
    return Response(response,
                    status=200,
                    mimetype='application/json')


@app.route('/citation/favoris/add', methods=['POST'])
def addCitationByIdAndPosterToFav():
    requestBoby = request.get_json()
    citationId = ObjectId(requestBoby.get('citationId'))
    poster = requestBoby.get('Poster')
    citation = mongo.db.citations.update(
   { '_id': citationId}, {'$inc': {"savedInFavorites": 1, }, '$addToSet':  {'likers' :{'name': poster,'login': poster }, } })
    response = dumps(citation)
    return Response(response,
                    status=200,
                    mimetype='application/json')


@app.route('/citation/favoris/del', methods=['POST'])
def deleteCitationByIdAndPosterToFav():
    requestBoby = request.get_json()
    citationId = ObjectId(requestBoby.get('citationId'))
    poster = requestBoby.get('Poster')
    citation = mongo.db.citations.update(
   { '_id': citationId},  {'$inc':  {   "savedInFavorites": -1,  }, '$pull':  {'likers' :{'login':poster }, } })
    response = dumps(citation)
    return Response(response,
                    status=200,
                    mimetype='application/json')


@app.route('/citation/ajouter', methods=['POST'])
def createNewCitation():
    requestBoby = request.get_json()
    
    author = requestBoby.get('author')
    year = requestBoby.get('year')
    nationality = requestBoby.get('nationality')
    citation = requestBoby.get('citation')
    poster = requestBoby.get('Poster')
    
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
                    mimetype='application/json')





'''

ROUTES STATISTIQUES

'''

@app.route('/citation/stats/<stat>', methods=['GET'])
def statCitations(stat):
    
    if stat == 'top3citation':
        citation = mongo.db.citations.find({}, { 'savedInFavorites': 1, 'citation': 1 }).sort([( 'savedInFavorites', -1 )]).limit(3)


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
                    mimetype='application/json')


if __name__ == "__main__":
    app.run(debug=True)