import sqlite3 as sl
import pandas as pd

def connect_csv_to_database(csv_file, db_file):
    # Create/Connect database
    conn = sl.connect(db_file)
    curs = conn.cursor()

    # Create our table
    # Manually specify table name, column names, and columns types
    curs.execute('DROP TABLE IF EXISTS incidents')
    curs.execute('CREATE TABLE IF NOT EXISTS '
                 'incidents (incident_id INTEGER PRIMARY KEY, date TEXT NOT NULL, '
                 'category INTEGER, grade INTEGER, severity INTEGER, system INTEGER)')
    conn.commit()  # don't forget to commit changes before continuing

    values = []
    with open(csv_file, 'r') as fin:
        for line in fin:
            line = line.strip()
            if line:
                line = line.replace('"', '')  # get rid of wrapping double quotes
                lineList = line.split(',')  # split on comma (CSV)
                # only accept rows w/ a last column that has a valid temp
                if lineList and lineList[-1].strip().isnumeric():
                    # Extract values: incident_id, date, category, grade, severity, system
                    valTuple = (lineList[0], lineList[1], lineList[2], lineList[3], lineList[4], lineList[5])
                    values.append(valTuple)

    for valTuple in values:
        stmt = 'INSERT OR IGNORE INTO incidents VALUES (?, ?, ?, ?, ?, ?)'
        curs.execute(stmt, valTuple)

    # Verify database content
    print('\nFirst 3 db results:')
    results = curs.execute('SELECT * FROM incidents').fetchmany(3)
    for result in results:
        print(result)

    # Count the number of rows in the database
    result = curs.execute('SELECT COUNT(*) FROM incidents').fetchone()
    print('\nNumber of valid db rows:', result[0])

    # Find the maximum severity in the database
    result = curs.execute('SELECT MAX(severity) FROM incidents').fetchone()
    print('Max Severity:', result[0])

    # Close the connection
    conn.commit()
    conn.close()
