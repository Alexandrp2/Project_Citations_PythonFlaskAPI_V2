import smtplib, email.mime.multipart, email.mime.text, uuid
from flask import Flask,Response, jsonify, json

class MailManager:
    
    def sendMsg(self, pseudo, mailUser, newPwdUuid):
        '''
        SMTP for outlook.fr
            Nom de serveur : smtp.office365.com
            Port : 587
            Méthode de chiffrement : STARTTLS

        SMTP for gmail.comm
            smtp.gmail.com
            SSL requis : oui
            TLS requis : oui (si disponible)
            Authentification requise : oui
            Port pour SSL : 465
            Port pour TLS/STARTTLS : 587
        '''

        '''
            Set here your 3 main messaging information
        '''
        serverName = 'insert the name of the messaging server which send the message (common examples: smtp.gmail.com, smtp.office365.com)'
        senderMail = 'insert here the mail of the entity (person, company) who send the message'
        senderMailPassword = 'insert here your password that connects the senderMail to the messaging server'


        msg = email.mime.multipart.MIMEMultipart()
        msg['From'] = senderMail
        msg['To'] = mailUser
        msg['Subject'] = 'Citations.fr - Nouveau mot de passe' 
        
        messageToSend = "Bonjour {0},\rVous avez perdu votre mot de passe sur notre site.\rPas de panique, en voici un nouveau que vous pourrez changer si vous le souhaitez: {1}\n\rCordialement,\rLe site citations.fr"
        message = messageToSend.format(pseudo, newPwdUuid)
        msg.attach(email.mime.text.MIMEText(message))
        mailserver = smtplib.SMTP(serverName, 587)
        mailserver.ehlo()
        mailserver.starttls()
        mailserver.ehlo()
        mailserver.login(senderMail, senderMailPassword)
        mailserver.sendmail(senderMail, mailUser, msg.as_string())
        mailserver.quit()
        return Response(response=json.dumps({"Status": "200"}),
                        status=200,
                        headers= {'X-Frame-Options': 'sameorigin', 'X-Content-Type-Options': 'nosniff'},
                        mimetype='application/json')