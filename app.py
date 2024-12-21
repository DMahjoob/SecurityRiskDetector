import datetime
import io
import os
import sqlite3 as sl

import pandas as pd
from flask import Flask, redirect, render_template, request, session, url_for, send_file
from matplotlib.figure import Figure
from sklearn.linear_model import LinearRegression
from CSV_to_DB_manual import connect_csv_to_database  # Import the function
from Week10WebDevelopment.ITP_216_H10_Mahjoob_Darius.util.FileDBHelper import db_set_food

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
db = "security_incidents.db"

def load_data(data):
    """
    Preprocessing all the data (only done once to make a new .csv file that is
    then passed into the database. Since it takes a long time to load, this function
    was used and only remains here as proof that the preprocessing work was done.
    This function saves a new csv file to use for future with only the important data.
    :param data: original dataframe (1 gigabyte in size)
    :return: None
    """
    # Make relevant non-numeric data numerical
    data["Severity"] = data.apply(calculate_combined_severity, axis=1)

    # We only want to use the columns that will be useful
    data_filtered = data[["IncidentId", "Timestamp",
                          "Category", "IncidentGrade",
                          "Severity", "OrgId"]]

    # Rename columns
    data_filtered = data_filtered.rename(
        columns={"IncidentId": "incident_id","Timestamp": "date","Category": "category",
                 "IncidentGrade": "grade", "Severity": "severity", "OrgId": "system"})

    # Convert date column to month/day/year and then fix all the data
    data_filtered["date"] = pd.to_datetime(data_filtered["date"]).dt.strftime("%m/%d/%y")
    data_filtered.fillna("Unknown", inplace=True)
    # print(data_filtered.head())
    # print(data_filtered.shape)
    data_filtered.to_csv("incidents.csv", index=False)

def calculate_combined_severity(row):
    """
    This function calculates the combined severity score for each row in the dataframe
    :param row: a given row in the dataframe
    :return: the combined severity score
    """
    # Map non-numeric values to numeric ones
    grade_map = {"TruePositive": 3, "BenignPositive": 2, "FalsePositive": 1}
    category_map = {"CommandAndControl": 5, "Exfiltration": 4, "Execution": 3,
                    "InitialAccess": 2, "Reconnaissance": 1}
    return grade_map.get(row["IncidentGrade"], 0) + category_map.get(row["Category"], 0)

@app.route("/")
def home():
    options = {
        "severity": "Incident Severity",
        "grade": "Malicious Grade Type"
    }
    return render_template("home.html",
                           categories=db_get_categories(),
                           message="Please select a category to analyze.",
                           options=options)


@app.route("/submit_system", methods=["POST"])
def submit_system():
    session["category"] = request.form["category"]
    if 'category' not in session or session["category"] == "":
        return redirect(url_for("home"))
    if "data_request" not in request.form:
        return redirect(url_for("home"))
    session["data_request"] = request.form["data_request"]
    return redirect(url_for("category_current",
                            data_request=session["data_request"],
                            category=session["category"]))


@app.route("/api/incidents/<data_request>/<category>")
def category_current(data_request, category):
    return render_template("system.html",
                           data_request=data_request,
                           category=category,
                           project=False)


@app.route("/submit_projection", methods=["POST"])
def submit_projection():
    if 'category' not in session:
        return redirect(url_for("home"))
    session["date"] = datetime.datetime.strptime(request.form["date"], '%Y-%m-%d').strftime('%m/%d/%y')
    return redirect(url_for("category_projection",
                            data_request=session["data_request"],
                            category=session["category"]))


@app.route("/api/incidents/<data_request>/projection/<category>")
def category_projection(data_request, category):
    return render_template("system.html",
                           data_request=data_request,
                           category=category,
                           project=True,
                           date=session["date"])


@app.route("/fig/<data_request>/<category>")
def fig(data_request, category):
    fig = create_figure(data_request, category)
    img = io.BytesIO()
    fig.savefig(img, format='png')
    img.seek(0)
    return send_file(img, mimetype="image/png")


def create_figure(data_request, category):
    df = db_create_dataframe(data_request, category)
    if data_request == "grade":
        grade_map = {"TruePositive": 3, "BenignPositive": 2, "FalsePositive": 1}
        df["grade"] = df["grade"].map(grade_map).fillna(0)

    df = df.groupby("date").mean().reset_index()

    if 'date' not in session:
        fig = Figure()
        ax = fig.add_subplot(1, 1, 1)
        fig.suptitle(category + " cases of type " + data_request.capitalize() + " by Date")
        ax.plot(df["date"], df[data_request], label='Historical Data')
        ax.legend()
        ax.set(xlabel="Date", ylabel=data_request.capitalize())
        fig.autofmt_xdate()
        return fig
    else:
        df['datemod'] = df['date'].map(datetime.datetime.toordinal)
        y = df[data_request][-30:].values
        X = df['datemod'][-30:].values.reshape(-1, 1)
        target_date = datetime.datetime.strptime(session['date'], '%m/%d/%y')
        draw = datetime.datetime.toordinal(target_date)

        # Linear Regression Model with prediction
        regr = LinearRegression(fit_intercept=True, copy_X=True, n_jobs=2)
        regr.fit(X, y)
        prediction = int(regr.predict([[draw]])[0])

        # make a new dataframe for prediction
        df_pred = pd.DataFrame({'date': [target_date], data_request: [prediction]})
        df = pd.concat([df, df_pred], ignore_index=True)

        fig = Figure()
        ax = fig.add_subplot(1, 1, 1)
        fig.suptitle('By ' + session['date'] + ' for ' + category + ' cases, the average '
                     + data_request.capitalize() + ' will be ' + str(prediction))

        ax.plot(df["date"][:-1], df[data_request][:-1], color="blue", label="Historical Data")
        ax.plot(df["date"][-2:], df[data_request][-2:], color="orange", label="Predicted Data")
        ax.legend()
        ax.set(xlabel="Date", ylabel=data_request.capitalize())
        fig.autofmt_xdate()
        return fig


def db_create_dataframe(data_request, system):
    conn = sl.connect(db)
    stmt = f"SELECT date, {data_request} FROM incidents WHERE category =?"
    df = pd.read_sql_query(stmt, conn, params = (system,))
    df['date'] = pd.to_datetime(df['date'], format='%m/%d/%y')
    conn.close()
    return df


def db_get_categories():
    conn = sl.connect(db)
    stmt = "SELECT DISTINCT category FROM incidents"
    categories = pd.read_sql_query(stmt, conn)["category"].tolist()
    conn.close()
    return categories

@app.route('/<path:path>')
def catch_all(path):
    return redirect(url_for("home"))


if __name__ == "__main__":
    pd.set_option('display.max_columns', None)
    # load_data(data) # only needed to be run once with the initial very messy database to remove all unnecessary information
    #                 # original dataset can be viewed at 'allIncidentInformation.csv' which was truncated to
    #                 # the new file that we will be using throughout -> incidents.csv
    csv_file = "csv/incidents.csv"
    # connect_csv_to_database(csv_file, db) # connect csv file to database
    app.secret_key = os.urandom(12)
    app.run(debug=True)
