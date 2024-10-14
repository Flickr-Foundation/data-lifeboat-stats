import collections
import json
import secrets

from authlib.integrations.httpx_client import OAuth1Client
from flask import abort, Flask, redirect, render_template, request, session, url_for
from flask_login import current_user, LoginManager, login_user, logout_user
from flask_wtf import FlaskForm
from flickr_photos_api import FlickrApi
from flickr_url_parser import parse_flickr_url
import keyring
from nitrate.xml import find_required_elem
import werkzeug
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired


app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex()

login_manager = LoginManager()
login_manager.init_app(app)


class FlickrUser:
    """
    A basic FlickrUser class to make flask-login happy.
    """

    def __init__(self, user_id: str):
        self.user_id = user_id
        self.is_active = True
        self.is_authenticated = True

    def get_id(self) -> str:
        return self.user_id


@login_manager.user_loader
def load_user(user_id: str) -> FlickrUser:
    return FlickrUser(user_id)


class FlickrForm(FlaskForm):
    url = StringField("URL", validators=[DataRequired()])
    submit = SubmitField("Go")


def get_api():
    if current_user.is_authenticated:
        client = OAuth1Client(
            client_id=keyring.get_password("flickr_api", "flask_demo_key"),
            client_secret=keyring.get_password("flickr_api", "flask_demo_secret"),
            signature_type="QUERY",
            token=session['token']["oauth_token"],
            token_secret=session['token']["oauth_token_secret"],
        )
        return FlickrApi(client=client)        
    else:
        return FlickrApi.with_api_key(
            api_key=keyring.get_password("flickr_api", "key"),
            user_agent="Alex Chan's personal scripts <alex@alexwlchan.net>",
        )


def get_photo_stats(url: str):
    parsed_url = parse_flickr_url(url)
    
    visibility = {
        'public': 0,
        'private': 0,
        'friends only': 0,
        'family only': 0,
        'friends and family': 0,
    }
    
    stats = {
        'licenses': collections.Counter(),
        'safety': collections.Counter(),
        'downloads_disabled': 0,
        'visibility': visibility,
    }
    
    api = get_api()
    
    if parsed_url['type'] == 'gallery':            
        data = api.call(
            method="flickr.galleries.getPhotos",
            params={
                "gallery_id": parsed_url["gallery_id"],
                "page": parsed_url["page"],
                "per_page": 500,
                "extras": "license,safety_level,url_o"}
        )
        
        photos = data.findall(".//photo")
    elif parsed_url['type'] == 'user':
        user_id = api._ensure_user_id(user_id=parsed_url['user_id'], user_url=parsed_url['user_url'])
        
        data = api.call(
            method="flickr.people.getPhotos",
            params={
                "user_id": user_id,
                "page": parsed_url["page"],
                "per_page": 500,
                "extras": "license,safety_level,url_o"
            }
        )
                    
        photos = data.findall(".//photo")
    elif parsed_url['type'] == 'album':
        print(parsed_url)
        
        user = api.get_user(user_url=parsed_url['user_url'])
                
        data = api.call(
            method="flickr.photosets.getPhotos",
            params={
                "user_id": user['id'],
                "photoset_id": parsed_url["album_id"],
                "page": parsed_url["page"],
                "per_page": 500,
                "extras": "license,safety_level,url_o"
            }
        )
        
        photos = data.findall(".//photo")
    elif parsed_url['type'] == 'group':        
        resp = api.call(
            method="flickr.urls.lookupGroup",
            params={"url": parsed_url["group_url"]},
        )
        
        group_elem = find_required_elem(resp, path=".//group")
        
        data = api.call(
            method="flickr.groups.pools.getPhotos",
            params={
                "group_id": group_elem.attrib["id"],
                "page": parsed_url["page"],
                "per_page": 500,
                "extras": "license,safety_level,url_o"
            }
        )
        
        photos = data.findall(".//photo")
    elif parsed_url["type"] == "tag":
        data = api.call(
            method="flickr.photos.search",
            params={
                "tags": parsed_url["tag"],
                "page": parsed_url["page"],
                "per_page": 500,
                "sort": "interestingness-desc",
                "extras": "license,safety_level,url_o"
            }
        )
        
        photos = data.findall(".//photo")
    else:
        assert 0
        photos = []
    
    for p in photos:
        if p.attrib['ispublic'] == '1':
            visibility['public'] += 1
        elif p.attrib['isfriend'] == '1' and p.attrib['isfamily'] == '1':
            visibility['friends and family'] += 1
        elif p.attrib['isfriend'] == '1':
            visibility['friends only'] += 1
        elif p.attrib['isfamily'] == '1':
            visibility['family only'] += 1
        else:
            visibility['private'] += 1
                    
        stats['safety'][{
            '0': 'safe', 
            '1': 'moderate',
            '2': 'restricted'
            }[p.attrib['safety_level']]] += 1
                        
        license_label = api.lookup_license_by_id(id=p.attrib['license'])['label']
        stats['licenses'][license_label] += 1
        
        if 'url_o' not in p.attrib:
            stats['downloads_disabled'] += 1
    
    return stats
    

@app.route("/", methods=["GET", "POST"])
def index():
    form = FlickrForm()
    
    if form.validate_on_submit():
        photo_stats = get_photo_stats(form.url.data)
    else:
        photo_stats = None
    
    if current_user.is_authenticated:
        user = session['token']['username'] + ' (' + session['token']['user_nsid'] + ')'
    else:
        user = 'public'
    
    return render_template("index.html", form=form, photo_stats=photo_stats, user=user)
    

@app.route("/authorize")
def log_in_with_flickr() -> werkzeug.Response:
    if current_user.is_authenticated:
        return redirect(url_for("indexc"))

    client = OAuth1Client(
        client_id=keyring.get_password("flickr_api", "flask_demo_key"),
        client_secret=keyring.get_password("flickr_api", "flask_demo_secret"),
        signature_type="QUERY",
    )

    # Step 1: Getting a Request Token
    #
    # See https://www.flickr.com/services/api/auth.oauth.html#request_token
    #
    # Note: we could put the next_url parameter in here, but this
    # causes issues with the OAuth 1.0a signatures, so I'm passing that
    # in the Flask session instead.
    redirect_url = url_for("flickr_auth_callback", _external=True)

    request_token_resp = client.fetch_request_token(
        url="https://www.flickr.com/services/oauth/request_token",
        params={"oauth_callback": redirect_url},
    )
    
    request_token = request_token_resp["oauth_token"]

    session["flickr_oauth_request_token"] = json.dumps(request_token_resp)

    # Step 2: Getting the User Authorization
    #
    # This creates an authorization URL on flickr.com, where the user
    # can choose to authorize the app (or not).
    #
    # See https://www.flickr.com/services/api/auth.oauth.html#request_token
    authorization_url = client.create_authorization_url(
        url="https://www.flickr.com/services/oauth/authorize?perms=read",
        request_token=request_token,
    )

    return redirect(authorization_url)


@app.route("/callback")
def flickr_auth_callback() -> werkzeug.Response:
    try:
        request_token = json.loads(session.pop("flickr_oauth_request_token"))
    except (KeyError, ValueError):
        abort(400)

    client = OAuth1Client(
        client_id=keyring.get_password("flickr_api", "flask_demo_key"),
        client_secret=keyring.get_password("flickr_api", "flask_demo_secret"),
        token=request_token["oauth_token"],
        token_secret=request_token["oauth_token_secret"],
    )

    client.parse_authorization_response(request.url)

    # Step 3: Exchanging the Request Token for an Access Token
    #
    # This token gets saved in the OAuth1Client, so we don't need
    # to inspect the response directly.
    #
    # See https://www.flickr.com/services/api/auth.oauth.html#access_token
    token = client.fetch_access_token(
        url="https://www.flickr.com/services/oauth/access_token"
    )
    
    session['token'] = token

    # The token will be of the form:
    #
    #     {'fullname': 'Alex Chan',
    #      'oauth_token': '…',
    #      'oauth_token_secret': '…',
    #      'user_nsid': '199258389@N04',
    #      'username': 'alexwlchan'}
    #
    # We only really care about the user NSID, because that's the thing
    # we want to match to our database.
    user = load_user(user_id=token["user_nsid"])

    if user is None:
        return redirect(url_for("index", result="flickr_login_okay"))
    else:
        login_user(user)
        return redirect(url_for("index"))


@app.route("/logout")
def logout() -> werkzeug.Response:
    logout_user()
    del session['token']
    return redirect(url_for("index"))
