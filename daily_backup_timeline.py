import sqlite3
import pandas as pd
import json
import datetime
connection = sqlite3.connect("/home/syed1/backend_ats/blocks.db")
df = pd.read_sql_query("SELECT * FROM all_timeline ORDER BY timestamp DESC", connection)
day = str(datetime.datetime.now().strftime("%d%m%Y"))
with open(f"/home/syed1/backend_ats/timelines/timeline-{day}.json", "w") as outfile:
	outfile.write(json.dumps(df.to_json(orient='records')))
