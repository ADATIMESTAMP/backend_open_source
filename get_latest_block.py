import koios_python
import pandas as pd
import datetime
import time
import sqlite3

kp = koios_python.URLs()
x=0
y=1000
temp_json1 = []
temp_json = kp.get_blocks(content_range=f"{x}-{y}")
for i in temp_json:
	temp_dict = ({key: i[key] for key in ['hash', 'epoch_no','abs_slot','epoch_slot','block_height','block_time']})
	temp_dict['block_date'] = datetime.datetime.fromtimestamp(int(i['block_time'])).strftime('%Y-%m-%d')
	temp_json1.append(temp_dict)
temp_df = pd.DataFrame(temp_json1)
temp_df['nft_used'] = False

connection = sqlite3.connect("/home/syed1/backend_ats/blocks.db")
for i in range(len(temp_df)):
	try:
		temp_df.iloc[i:i+1].to_sql("all_blocks", connection, index=False, if_exists='append')
	except:
		pass
cursor = connection.cursor()
cursor.execute("DELETE FROM all_blocks WHERE block_date <= date('now','-10 day')")
connection.commit()
connection.close()
