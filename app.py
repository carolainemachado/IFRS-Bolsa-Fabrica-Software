import os
import requests
from flask import Flask, session, abort, redirect, request, render_template
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask("Google Login App")
app.secret_key = "CodeSpecialist.com"

# permite solicitações HTTP não seguras durante o desenvolvimento
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "30319127849-ndeqp6l00qostl95ek594svn6r0168cl.apps.googleusercontent.com"

# configuração das credenciais do cliente
CLIENT_CONFIG = {
    'web': {
        'client_id': '30319127849-ndeqp6l00qostl95ek594svn6r0168cl.apps.googleusercontent.com',
        'client_secret': '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',
        'redirect_uris': ['http://127.0.0.1:5000/callback'],
        'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
        'token_uri': 'https://oauth2.googleapis.com/token',
        'token_introspection_uri': 'https://oauth2.googleapis.com/tokeninfo',
        'userinfo_uri': 'https://openidconnect.googleapis.com/v1/userinfo',
    }
}
# fluxo de autorização
flow = Flow.from_client_config(
    CLIENT_CONFIG,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# função decoradora para verificar se o login é necessário
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


# render_template faz a comunicação com o HTML
@app.route("/")
def index():
    return render_template('index.html')

# rota para iniciar o processo de login
@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

# rota de retorno do Google após a autorização
@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")


@app.route("/logout")
def logout():
    session.clear()# limpa a sessão
    return redirect("/")


@app.route("/protected_area")
@login_is_required
def protected_area():
    return f"Bem vinda, {session['name']}! <br/> <a href='/logout'><button>Sair</button></a>"


if __name__ == "__main__":
    app.run(debug=True)