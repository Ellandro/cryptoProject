#from crypt import methods
import base64
from datetime import datetime

from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
#from flask_log import login_required

from flask_migrate import Migrate
from sqlalchemy.sql.functions import current_user
from werkzeug.security import check_password_hash, generate_password_hash

from models import Message, db, User, Conversation

app = Flask(__name__)
app.secret_key = '\xad\xc5\xb1\xe5z\x92\x08\xbfk\x7f\xde*\n\xd2\x04\xcd9\xa0\x18\x92y:SG'  # Nécessaire pour `flash`
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Lan087743@localhost/EpsiMessage'

migrate = Migrate(app, db)
db.init_app(app)
# Créer les tables si elles n'existent pas déjà
with app.app_context():
    db.create_all()
@app.route('/register', methods = ["POST", "GET"])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('usermail')
        password = request.form.get('password')

        user = User(username=username, mail=email)
        user.set_password(password)
        user.generate_keys()  # Génération des clés RSA
        db.session.add(user)
        db.session.commit()

        flash('Compte créé avec succès. Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Recherche l'utilisateur par son nom d'utilisateur
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            # Connexion réussie, stocke l'ID et l'email dans la session
            session['user_id'] = user.id
            print(user.id)
            
            session['user_mail'] = user.mail
            flash('Connexion réussie!')
            return redirect(url_for('inbox'))  # Redirige vers la boîte de réception après la connexion
        else:
            flash('Nom d’utilisateur ou mot de passe incorrect.')

    return render_template('login.html', current_user = ' ')


@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = db.session.get(User, session['user_id'])

    if request.method == 'POST':
        recipient_mail = request.form.get('recipient_mail')
        message_text = request.form.get('message')

        recipient = User.query.filter_by(mail=recipient_mail).first()
        if not recipient:
            flash('Destinataire non trouvé.', 'error')
            return redirect(url_for('index'))

        # Crypter le message
        try:
            encrypted_message = recipient.encrypt_message(message_text)
        except Exception as e:
            flash(f'Erreur de cryptage: {str(e)}', 'error')
            return redirect(url_for('inbox', usermail=recipient_mail))

        # Gérer la conversation
        conversation = None
        for conv in current_user.conversations:
            if recipient in conv.participants:
                conversation = conv
                break

        if not conversation:
            conversation = Conversation()
            conversation.participants.extend([current_user, recipient])
            db.session.add(conversation)
            db.session.flush()

        new_message = Message(
            conversation_id=conversation.id,
            sender_id=current_user.id,
            receiver_id=recipient.id,
            message=encrypted_message
        )

        db.session.add(new_message)
        db.session.commit()

        flash('Message envoyé avec succès!', 'success')
        return redirect(url_for('inbox', usermail=recipient.mail))

    return render_template('index.html', current_user=current_user)


@app.route('/inbox')
@app.route('/inbox/<usermail>')
def inbox(usermail=None):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = db.session.get(User, session['user_id'])
    conversations = current_user.conversations

    selected_conversation = None
    if usermail:
        recipient = User.query.filter_by(mail=usermail).first()
        if recipient:
            for conv in conversations:
                if recipient in conv.participants:
                    selected_conversation = conv
                    break

    for conversation in conversations:
        messages = Message.query.filter(
            Message.conversation_id == conversation.id,
            (Message.receiver_id == current_user.id) |
            ((Message.sender_id == current_user.id) & (Message.receiver_id != current_user.id))
        ).order_by(Message.timestamp).all()

        for message in messages:
            try:
                message.decrypted_content = current_user.decrypt_message(message.message)
            except Exception as e:
                message.decrypted_content = f"Erreur de décryptage: {str(e)}"

    unread_count = Message.query.filter_by(
        receiver_id=current_user.id,
        is_read=False
    ).count()

    return render_template(
        'inbox.html',
        conversations=conversations,
        current_user=current_user,
        selected_conversation=selected_conversation,
        unread_count=unread_count
    )

@app.route('/conversation/<int:conversation_id>', methods=['GET', 'POST'])
def conversation_detail(conversation_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = db.session.get(User, session['user_id'])
    conversation = Conversation.query.get_or_404(conversation_id)

    if current_user not in conversation.participants:
        flash("Vous n'avez pas accès à cette conversation.", "danger")
        return redirect(url_for('inbox'))

    if request.method == 'POST':
        message_text = request.form.get('message')
        if message_text:
            recipient = next(p for p in conversation.participants if p != current_user)

            try:
                # Crypter le message pour le destinataire ET pour l'expéditeur
                encrypted_for_recipient = recipient.encrypt_message(message_text)
                encrypted_for_sender = current_user.encrypt_message(message_text)

                new_message = Message(
                    conversation_id=conversation.id,
                    sender_id=current_user.id,
                    receiver_id=recipient.id,
                    message=encrypted_for_recipient  # Version cryptée pour le destinataire
                )

                # Stocker la version cryptée pour l'expéditeur dans une nouvelle table
                sender_message = Message(
                    conversation_id=conversation.id,
                    sender_id=current_user.id,
                    receiver_id=current_user.id,  # Le récepteur est l'expéditeur lui-même
                    message=encrypted_for_sender
                )

                db.session.add(new_message)
                db.session.add(sender_message)
                db.session.commit()
                flash("Message envoyé.", "success")

            except Exception as e:
                flash(f"Erreur lors de l'envoi du message: {str(e)}", "error")

            return redirect(url_for('conversation_detail', conversation_id=conversation.id))

    # Récupérer tous les messages de la conversation
    messages = Message.query.filter(
        Message.conversation_id == conversation.id,
        (Message.receiver_id == current_user.id) |
        ((Message.sender_id == current_user.id) & (Message.receiver_id != current_user.id))
    ).order_by(Message.timestamp).all()

    for message in messages:
        # Stocker la version encodée en base64 pour l'affichage
        message.encrypted_content = base64.b64encode(message.message).decode('utf-8')

        try:
            # Décrypter le message
            message.decrypted_content = current_user.decrypt_message(message.message)
        except Exception as e:
            message.decrypted_content = f"Erreur de décryptage: {str(e)}"

    return render_template(
        'conversation_detail.html',
        conversation=conversation,
        messages=messages,
        current_user=current_user
    )


@app.route('/new-conversation', methods=['POST'])
def new_conversation():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = db.session.get(User, session['user_id'])

    recipient_mail = request.form.get('recipient_mail')
    first_message = request.form.get('first_message')

    # Vérifier si le destinataire existe
    recipient = User.query.filter_by(mail=recipient_mail).first()
    if not recipient:
        flash('Utilisateur non trouvé.', 'error')
        return redirect(url_for('inbox'))

    # Vérifier si une conversation existe déjà
    existing_conversation = None
    for conv in current_user.conversations:
        if recipient in conv.participants:
            existing_conversation = conv
            break

    if existing_conversation:
        # Ajouter seulement le nouveau message
        message = Message(
            conversation_id=existing_conversation.id,
            sender_id=current_user.id,
            receiver_id=recipient.id,
            message=first_message
        )
        db.session.add(message)
    else:
        # Créer une nouvelle conversation avec le premier message
        conversation = Conversation()
        conversation.participants.extend([current_user, recipient])
        db.session.add(conversation)
        db.session.flush()  # Pour obtenir l'ID de la conversation

        message = Message(
            conversation_id=conversation.id,
            sender_id=current_user.id,
            receiver_id=recipient.id,
            message=first_message
        )
        db.session.add(message)

    db.session.commit()

    flash('Message envoyé avec succès!', 'success')
    return redirect(url_for('inbox'))


@app.route('/search-users')
def search_users():
    if 'user_id' not in session:
        return jsonify([])

    query = request.args.get('query', '').lower()
    users = User.query.filter(
        (User.mail.like(f'%{query}%') | User.username.like(f'%{query}%')) &
        (User.id != session['user_id'])  # Exclure l'utilisateur actuel
    ).limit(5).all()

    return jsonify([{
        'id': user.id,
        'username': user.username,
        'mail': user.mail
    } for user in users])



@app.route('/logout')
def logout():
    # Supprimer l'ID de l'utilisateur de la session
    session.pop('user_id', None)

    # Flash un message de succès (facultatif)
    flash('Vous avez été déconnecté avec succès!', 'success')

    # Rediriger l'utilisateur vers la page d'accueil ou la page de connexion
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=3000)
