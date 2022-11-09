import os

from flask import Flask, render_template, request, session, flash, redirect, url_for
from python_graphql_client import GraphqlClient

app = Flask(__name__)
app.config.from_prefixed_env()

myOrg = app.config['GH_ORG']

#
# Root entry page
#
@app.route("/")
def index():
  return render_template("login.html")


#
# Login Page
#   
@app.route('/login', methods=['GET', 'POST'])
def login():

    error = None

    if request.method == 'POST':
        if request.form['username'] != app.config['USERNAME']:
            error = 'Invalid username or password combination'
        elif request.form['password'] != app.config['PASSWORD']:
            error = 'Invalid username or password combination'
        else:
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('vulns'))

    return render_template('login.html', error=error)


#
# Vulnerability list
#
@app.route("/vulns")
def vulns():

    list = fetch()
    context = {
        'repo_list': list[0],
        'issues': list[1],
        'repos': list[2],
        'pct': list[3],
        'myOrg': myOrg,
    }
    return render_template("vulns.html", context=context)


#
# Logout Page
#
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('index'))


##
## constuct the GitHub GraphQL query (with cursor)
##
def gqlQuery(after_cursor=None):
    return """
query {
  organization(login: "GHORG") {
    repositories(first: 100, after:AFTER, orderBy: {field:NAME, direction:ASC}) {
      totalCount
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        name
        vulnerabilityAlerts(first: 10, states: OPEN) {
          totalCount
        }
      }
    }
  }
}
""".replace(
        "AFTER", '"{}"'.format(after_cursor) if after_cursor else "null"
    ).replace(
      "GHORG", myOrg
    )


##
##
##
class Repo:
  name = ""
  vulns = 0

client = GraphqlClient(endpoint="https://api.github.com/graphql")

def fetch():

    total_repos = 0
    total_issues = 0

    has_next_page = True
    after_cursor = None

    repoList = []

    while has_next_page:

        data = client.execute(
            query = gqlQuery(after_cursor),
            headers = {"Authorization": "Bearer {}".format(app.config['GH_PAT'])},
        )

        total_repos   = data["data"]["organization"]["repositories"]["totalCount"]
        has_next_page = data["data"]["organization"]["repositories"]["pageInfo"]["hasNextPage"]
        after_cursor  = data["data"]["organization"]["repositories"]["pageInfo"]["endCursor"]

        for aRepo in data["data"]["organization"]["repositories"]["nodes"]:

            no_of_vulns = aRepo["vulnerabilityAlerts"]["totalCount"]
            if (no_of_vulns > 0):
                thisRepo = Repo()
                thisRepo.name = aRepo["name"]
                thisRepo.vulns = no_of_vulns
                total_issues = total_issues + no_of_vulns
                repoList.append(thisRepo)

    pct = float("{:.1f}".format(len(repoList) / total_repos * 100))

    return [repoList, total_issues, total_repos, pct]