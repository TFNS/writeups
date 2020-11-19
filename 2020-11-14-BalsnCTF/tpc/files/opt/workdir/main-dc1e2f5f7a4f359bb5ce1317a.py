import urllib.request

from flask import Flask, request

app = Flask(__name__)


@app.route("/query")
def query():
    site = request.args.get('site')
    text = urllib.request.urlopen(site).read()
    return text


@app.route("/")
def hello_world():
    return "/query?site=[your website]"


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8000)

