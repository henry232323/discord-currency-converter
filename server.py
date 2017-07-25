import asyncio
import logging
import secrets
import traceback
from urllib.parse import urlencode

import asyncpg
import aiohttp
from kyoukai import Kyoukai
from kyoukai.asphalt import HTTPRequestContext, Response
from werkzeug.exceptions import HTTPException
from werkzeug.utils import redirect
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

try:
    import ujson as json
except ImportError:
    import json

example_post = {
    "bot_id": 305177429612298242,
    "to_bot": "Tatsumaki",
    "amount": 5000,
    "user_id": 122739797646245899,
    "server_id": 166349353999532035
}

bot_db = {
        'id': 305177429612298242,
        'url': "http://api.typheus.me",
        'name': "RPGBot",
        'type': 0
}

user_db = {
    'user_id': 122739797646245899,
    'bots': [305177429612298242],
    'token': 'hsbrbrjsjsbe',
    'type': 0,  # 0 for hook 1 for gather
}

example_hook = {
    "from_bot": "RPGBot",
    "amount": 5000,
    "server_id": 166349353999532035,
    "to_bot": "Tatsumaki"
}

register = {
    'user_id': 122739797646245899,
}


class API(Kyoukai):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pool = None

        with open("auth", 'r') as af:
            self.client_id, self.client_secret = json.loads(af.read())

        self.session = aiohttp.ClientSession(loop=self.loop,
                                             json_serialize=json.loads,
                                             #auth=aiohttp.BasicAuth(self.client_id, self.client_secret),

                                             )
        self.logger = logging.getLogger('kyoukai')
        self.logger.setLevel(logging.INFO)
        self.handler = logging.FileHandler(filename="transactions.log",
                                           encoding='utf-8',
                                           mode='a')
        self.handler.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(name)s: %(message)s'))
        self.logger.addHandler(self.handler)

        with open("register.html") as _rf:
            self.register_html = _rf.read()

        @self.route("/code", methods=["GET"])
        async def code(ctx: HTTPRequestContext):
            try:
                if 'code' not in ctx.request.args:
                    return redirect("/register", code=303)

                code = ctx.request.args["code"]
                #creds = b64encode(quote(f"{self.client_id}:{self.client_secret}").encode()).decode()
                data = {
                        "code": code,
                        "grant_type": "authorization_code",
                        "redirect_uri": "https://rhodochrosite.xyz/authorize",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret
                    }
                response = await self.session.post(
                    f"https://discordapp.com/api/oauth2/token?{urlencode(data)}",
                )
                js = await response.json()
                token = js['access_token']
                return redirect(f"/authorize?token={token}", code=303)
            except:
                traceback.print_exc()

        @self.route("/authorize", methods=["GET"])
        async def authorize(ctx: HTTPRequestContext):
            try:
                if "token" not in ctx.request.args:
                    return redirect("/register", code=303)
                token = ctx.request.args['token']
                api_resp = await self.session.get("https://discordapp.com/api/users/@me",
                                                  headers={
                                                      "Authorization": f"Bearer {token}",
                                                  })
                js = await api_resp.json()
                if "code" in js:
                    return Response("An error occurred", status=500)

                async with self.pool.acquire() as connection:
                    exists = await connection.fetch(
                        f"""SELECT * FROM userdata WHERE user_id = {js['id']}"""
                    )

                    if exists:
                        js = {
                            "user_id": js["id"],
                            "bots": exists[0]["bots"],
                            "token": exists[0]["token"]
                        }
                    else:
                        token = secrets.token_urlsafe(48)

                        await connection.fetch(
                            f"""INSERT INTO userdata VALUES (
                                {js["id"]},
                                ARRAY[]::bigint[],
                                '{token}',
                                0
                            );"""
                        )

                        js = {
                            "user_id": js["id"],
                            "bots": [],
                            "token": token,
                        }

                return Response(json.dumps(js, indent=4), status=200, content_type="text/json")
            except:
                traceback.print_exc()

        @self.route("/", methods=["GET"])
        async def index(ctx: HTTPRequestContext):
            return redirect("/register", code=303)

        @self.route("/register", methods=["GET"])
        async def register(ctx: HTTPRequestContext): #  Post form to complete registration, GET to see register page
            return Response(self.register_html, content_type="text/html", status=200)

        @self.route("/add/", methods=["GET", "POST"])
        async def add(ctx: HTTPRequestContext):
            if ctx.request.method == "POST":
                if "Authorization" not in ctx.request.headers:
                    return HTTPException("Failed to provide token!",  # Token was omitted from the headers
                                         response=Response("Failed to fetch info!", status=401))
                return Response(status=503)
            else:
                return Response(status=503)

        @self.route("/bots/<int:snowflake>/", methods=["GET", "POST"])  # Post to `/bots/:bot_id/` with token in headers
        async def convert(ctx: HTTPRequestContext, snowflake: int):
            if ctx.request.method == "GET":
                snowflake = int(snowflake)
                async with self.pool.acquire() as connection:
                    response = await connection.fetch(
                        f"""SELECT * FROM botdata WHERE id = {snowflake}"""
                    )
                return Response(json.dumps(dict(response[0]), indent=4), status=200, content_type="text/json")
            else:
                try:
                    if "Authorization" not in ctx.request.headers:
                        return HTTPException("Failed to provide token!",  # Token was omitted from the headers
                                             response=Response("Failed to fetch info!", status=401))
                    token = ctx.request.headers["Authorization"]  # The user token
                    snowflake = int(snowflake)  # The bot snowflake
                    req = f"""SELECT * FROM userdata WHERE token = '{token.replace("'", "''")}';"""
                    async with self.pool.acquire() as connection:
                        response = await connection.fetch(req)  # Get bots and webhook / gather type
                    if response:
                        bots, type = response[0]["bots"], response[0]["type"]
                        if snowflake not in bots:  # That bot is not associated with that token
                            return HTTPException("That snowflake is not valid!", Response("Failed to fetch info!", status=401))

                        async with self.pool.acquire() as connection:
                            name = await connection.fetchval(
                                f"""SELECT name FROM botdata WHERE id = {snowflake};"""
                            )  # Get the bot's name
                            url = await connection.fetchval(
                                f"""SELECT url FROM botdata WHERE name = '{ctx.request.form["to_bot"].replace("'", "''")}';"""
                            )  # Get the URL of the bot we're sending to
                        if url is None:  # That bot is not in our database!
                            return HTTPException("That is an invalid bot!", response=Response("Failed to fetch info!", status=400))

                        payload = {
                            "from_bot": name,
                            "amount": ctx.request.form["amount"],
                            "to_bot": ctx.request.form["to_bot"],
                            "server_id": ctx.request.form["server_id"]
                        }
                        dumped = json.dumps(payload, indent=4)

                        if type is 0:  # If using webhooks
                            try:
                                await self.session.post(url, json=dumped)  # Post the payload to the other bot's URL
                            except Exception as e:
                                return HTTPException("An error occurred forwarding to the bot!", response=Response(e, status=500))

                        return Response(dumped, status=200, content_type="text/json")
                    else:  # If we don't get a response from the given token, the token doesn't exist
                        return HTTPException("Invalid token!", response=Response("Failed to fetch info!", status=401))
                except:  # Generic error catching, always gives 400 cause how could it be _my_ issue?
                    return HTTPException("An error occurred!", response=Response("Failed to fetch info!", status=400))

    async def connect(self):
        self.pool = await asyncpg.create_pool(user='root', password='root',
                                              database='discoin', host='127.0.0.1')

    async def host(self):  # Start the connection to the DB and then start the Kyoukai server
        await self.connect()
        #asyncio.ensure_future(eval.repl(self))
        await self.start('0.0.0.0', 1996)

loop = asyncio.get_event_loop()
api = API("discoin", loop=loop)
loop.create_task(api.host())
loop.run_forever()
