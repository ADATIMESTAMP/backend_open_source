from flask import Flask, request, jsonify, render_template
import requests
import base64
import json
import sys
import datetime
from datetime import timedelta
import math
import pandas as pd
from functools import wraps
from flask import request
import os
import uuid
from PIL import Image, ImageOps
from io import BytesIO
import urllib

import sqlite3

import random
import pyshorteners
shortener = pyshorteners.Shortener()

import koios_python
kp2 = koios_python.URLs(url='https://api.koios.rest/api/v1/', bearer="") ### Password

from flask_cors import CORS, cross_origin

from boto3 import session
from botocore.client import Config

import hashlib
import re

session = session.Session()

# create the flask app
app = Flask(__name__)

#CORS(app)
#CORS(app, supports_credentials=False, origins=["http://localhost:3000"])


@app.route("/login")
def login():
  return jsonify({'success': 'ok'})


pinata_url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
pinata_key = "" ### Password
pinata_headers = {'Authorization': 'Bearer ' + pinata_key}

spawn_headers = {'Authorization': ''} ### Password
spawn_url = "https://opts-api.spawningaiapi.com/api/v2/parity/urls/"


def check_auth(username, password):
    return username == '' and password == '' ### Password

def login_required(f):
    """ basic auth for api """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def resize_image(large_image, width=500, height=740):
    new_im = Image.open(BytesIO(base64.b64decode(large_image)))
    new_im = new_im.convert('RGB')
    new_im.thumbnail((width,height), Image.ANTIALIAS)
    x, y = new_im.size
    b_width = (width-x)//2 if width - x > 0 else 0
    b_height = (height-y)//2 if height - y > 0 else 0
    b_im = ImageOps.expand(new_im, border=(b_width,b_height), fill=(29,34,54))
    buffered = BytesIO()
    b_im.save(buffered, format="JPEG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return img_str

def upload_image(link, nft_name_with_block, render_type, is_img, is_thumb):
    if is_img:
        base64_message = resize_image(link)
    else:
        base64_message = link
    client = session.client('s3',
        region_name='ams3',
        endpoint_url='https://adamoments.ams3.digitaloceanspaces.com',
        aws_access_key_id="", ### Password
        aws_secret_access_key="") ### Password

    base64_decode_image = BytesIO(base64.b64decode(base64_message))
    client.put_object(Bucket='mainnet_images', Key=nft_name_with_block, Body=base64_decode_image, ContentType=render_type, ACL='public-read')
    if is_thumb:
        return f"https://adamoments.ams3.cdn.digitaloceanspaces.com/mainnet_images/{nft_name_with_block}"
    pinata_metadata = {"name": nft_name_with_block}
    pinata_payload = {"pinataMetadata": pinata_metadata}
    files = {"file": (nft_name_with_block, BytesIO(base64.b64decode(base64_message)))}
    ipfs_link = ""
    try:
        response = requests.post(pinata_url, headers = pinata_headers, files = files)
        ipfs_link = response.json()['IpfsHash']
    except:
        print(response.json())

    return ipfs_link

def store_metadata(nft_name, display_name, message, block_hash, archive_value, am_version, render_type, stake_address, ipfs_link, mint_price, mint_type, am_link, thumbnail):
    timestamp = str(datetime.datetime.now())
    moment = nft_name.replace("MOMENT-", "").replace("-H", ":").split(":")[0]
    alt_link = f"https://adamoments.ams3.cdn.digitaloceanspaces.com/mainnet_images/{nft_name}"
    ipfs_link = ipfs_link
    print(archive_value, ipfs_link, stake_address)
    hashed_val = "" ### Password
    salt = "" ### Password
    hashed_password = hashlib.sha512(hashed_val.encode('utf-8') + salt.encode('utf-8')).hexdigest()

    payload = {"urls":[{"url":f"https://gateway.pinata.cloud/ipfs/{ipfs_link}", "optOut":True, "optIn":False}]}
    try:
        requests.post(spawn_url, headers=spawn_headers, json=payload).json()
    except:
        pass

    connection = sqlite3.connect("blocks.db")
    moment_num = int(pd.read_sql_query("SELECT max(moment_num) as a FROM all_timeline", connection)["a"][0]) + 1
    cursor = connection.cursor()
    #cursor.execute(f"INSERT INTO all_timeline (nft_name, name, message, moment, block_hash, archive, am_version, ipfs_link, alt_link, stake_address, render_type, like_count, hide, grey, moment_num, timestamp, mint_price, mint_type, am_hash, am_link) VALUES ('{nft_name}', '{display_name}', '{message}', '{moment}', '{block_hash}', '{archive_value}', '{am_version}', '{ipfs_link}', '{alt_link}', '{stake_address}', '{render_type}', 0, 0, 0, '{moment_num}', '{timestamp}', '{mint_price}', '{mint_type}', '{hashed_password}', '{am_link}')")
    sql = "INSERT INTO all_timeline (nft_name, name, message, moment, block_hash, archive, am_version, ipfs_link, alt_link, stake_address,render_type, like_count, hide, grey, moment_num, timestamp, mint_price, mint_type, am_hash, am_link, thumbnail) VALUES (?, ?, ?, ?, ?,?, ?, ?, ?, ?,?, ?, ?, ?, ?,?, ?, ?, ?, ?, ?)"
    params = (
        nft_name,
        display_name,
        message,
        moment,
        block_hash,
        archive_value,
        am_version,
        ipfs_link,
        alt_link,
        stake_address,
        render_type,
        0,                  # like_count
        0,                  # hide
        0,                  # grey
        moment_num,
        timestamp,
        mint_price,
        mint_type,
        hashed_password,
        am_link,
	thumbnail
    )
    cursor.execute(sql, params)
    connection.commit()
    connection.close()
    return None

def get_free_block(nft_name, block_height):
    connection = sqlite3.connect("blocks.db")
    df = pd.read_sql_query("SELECT * from all_blocks", connection)
    if not (block_height is None):
        df2 = df[(df['block_height'] == int(block_height)) & (df['nft_used'] == False)]
        nft_name = df2['block_date'].iloc[0]
    else:
        df2 = df[(df['block_date'] == nft_name) & (df['nft_used'] == False)]
    if len(df2)==0:
        df2 = df
    df2 = df2.sample(axis=0)
    block_hash = df2['hash'].iloc[0]
    block_slot = int(df2['epoch_slot'].iloc[0])
    block_epoch = int(df2['epoch_no'].iloc[0])
    nft_name_with_block = f"MOMENT-{nft_name}-H{int(df2['block_height'].iloc[0])}"
    cursor = connection.cursor()
    cursor.execute(f"UPDATE all_blocks SET nft_used = 1 where hash = '{block_hash}'")
    connection.commit()
    connection.close()
    return (nft_name_with_block, block_hash)

@app.route('/buy', methods=['POST', 'OPTIONS'])
@login_required
def predict():
    nft_name = request.json.get('day')
    block_height = request.json.get('block')
    display_name = request.json.get('display_name')
    message = request.json.get('message')
    archive_value = request.json.get('archive_value')
    is_img = request.json.get('is_img')
    render_type = request.json.get('render_type')
    link = request.json.get('image')
    stake_address = request.json.get('stake_address')
    mint_price = request.json.get('mint_price')
    mint_type = request.json.get('mint_type')

    nft_name_with_block, block_hash = get_free_block(nft_name, block_height)
    am_version = "530-540"
    am_link = request.json.get('am_link')
    thumbnail = request.json.get('thumbnail')

    ipfs_link = upload_image(link, nft_name_with_block, render_type, is_img, False)
    if(len(thumbnail)>10):
    	thumbnail = upload_image(thumbnail, nft_name_with_block + "_thumbnail", 'image/png', False, True)
    store_metadata(nft_name_with_block, display_name, message, block_hash, archive_value, am_version, render_type, stake_address, ipfs_link, mint_price, mint_type, am_link, thumbnail)
    return json.dumps({"success":"ok"})

@app.route('/timeline', methods=['GET','POST'])
@cross_origin(origin='*')
@login_required
def timeline():
    connection = sqlite3.connect("blocks.db")
    all_likes = pd.read_sql_query("SELECT * FROM all_timeline a LEFT JOIN (SELECT nft_name, count(*) as comment_count FROM all_comments GROUP BY 1) b USING(nft_name) ORDER BY timestamp DESC", connection)
    moment_views = pd.read_sql_query("SELECT * FROM moment_views", connection)
    moment_views_dict = dict(zip(moment_views.iloc[:, 0], moment_views.iloc[:, 1]))
    timeline = list(all_likes.to_dict(orient="records"))
    old_timeline = []
    x = 1039
    for i in timeline:
        x = x+1
        old_timeline.append({i["nft_name"]:{"Metadata":{"Archive":i["archive"],
                     "Image":i["ipfs_link"],
                     "RenderType":i["render_type"],
                     "PoolLink":f'https://pool.pm/{i["policy_id_asset_id"].split(":")[-1]}' if i["policy_id_asset_id"] is not None else "NULL",
                     "AltImage":i["alt_link"],
                     "Title":i["name"],
                     "Message":''.join(i["message"]),
                     "Moment":i["nft_name"].split("-H")[0].replace("MOMENT-", ""),
                     "BlockHeight":i["nft_name"].split("-H")[1],
                     "BlockUrl":f"https://eutxo.org/block/{i['block_hash']}",
                     "like_count":int(i["like_count"]),
                     "am_link":i["am_link"],
                     "comment_count": int(i["comment_count"]) if i["comment_count"] == i["comment_count"] else 0,
                    "Total_Views": int(moment_views_dict.get(i["nft_name"])) if moment_views_dict.get(i["nft_name"]) else 0
                    },
                 "Appendix":{"NmkrBuyLink":"None",
                    "MomentNum":int(i['moment_num']),
                    "PolicyId":"None",
                    "Hide":int(i["hide"]),
                    "Created_By":i["stake_address"],
                    "Creator_URL":f"https://cexplorer.io/stake/{i['stake_address']}",
                    "uid":"NULL", 
                    "Created_On":i["timestamp"], 
                    "ReceiverAddress":"NULL",
                    "MintPrice":i["mint_price"],
                    "MintType":i["mint_type"],
                    "AmHash":i["am_hash"],
                    "NftID":i["policy_id_asset_id"],
		    "Thumbnail":i["thumbnail"],
                    "Grey":int(i["grey"])}
                }
           })

    return old_timeline

@app.route('/subscribe', methods=['GET', 'POST'])
@login_required
def subscribe():
    email = request.json.get('email')
    update_consent = request.json.get('update_consent')
    marketing_consent = request.json.get('marketing_consent')
    feedback_consent = request.json.get('feedback_consent')
    timestamp = request.json.get('timestamp')
    connection = sqlite3.connect("blocks.db")
    email_df = pd.DataFrame({"email":email, "update_consent":update_consent, "marketing_consent":marketing_consent, "feedback_consent":feedback_consent, "timestamp":timestamp}, index=[0])
    email_df.to_sql("all_emails", connection, if_exists='append', index=False)
    connection.close()
    return json.dumps({"success":"ok"})

@app.route('/share_comment', methods=['GET', 'POST'])
@login_required
def share_comment():
    # nft_name = request.json.get('nft_name')
    # comment = request.json.get('comment')
    # timestamp = request.json.get('timestamp')
    # stake_address = request.json.get('stake_address')
    # comment_id = request.json.get('comment_id')
    # connection = sqlite3.connect("blocks.db")
    # email_df = pd.DataFrame({"nft_name":nft_name, "comment":comment, "timestamp":timestamp, "stake_address":stake_address, "comment_id":comment_id}, index=[0])
    # email_df.to_sql("all_comments", connection, if_exists='append', index=False)
    # connection.close()
    # return json.dumps({"success":"ok"})
    data = request.get_json()
    nft_name = data.get('nft_name')
    comment = data.get('comment')
    timestamp = data.get('timestamp')
    stake_address = data.get('stake_address')
    comment_id = data.get('comment_id')
    parent_comment_id = data.get('parent_comment_id')

    if not all([nft_name, comment, timestamp, stake_address, comment_id]):
        return jsonify({"error": "Missing required fields"}), 400

    connection = None
    try:
        connection = sqlite3.connect("blocks.db")
        cursor = connection.cursor()

        query = """
            INSERT INTO all_comments (
                nft_name,
                comment,
                timestamp,
                stake_address,
                comment_id,
                parent_comment_id
            ) VALUES (?, ?, ?, ?, ?, ?)
        """
        
        params = (
            nft_name,
            comment,
            timestamp,
            stake_address,
            comment_id,
            parent_comment_id
        )

        cursor.execute(query, params)
        connection.commit()

        return jsonify({"success": "ok"})

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({"error": "Failed to post comment due to a database error."}), 500
    finally:
        if connection:
            connection.close()

@app.route('/see_comments', methods=['GET', 'POST'])
@login_required
def see_comments():
    nft_name = request.json.get('nft_name')
    if not nft_name:
        return jsonify({"error": "nft_name is required"}), 400

    connection = sqlite3.connect("blocks.db")
    connection.row_factory = sqlite3.Row  
    cursor = connection.cursor()

    query = """
        SELECT
            c.comment_id,
            c.like_count,
            c.comment,
            c.stake_address,
            c.timestamp,
            c.parent_comment_id,
            b.user_name
        FROM all_comments c
        LEFT JOIN all_bios b ON c.stake_address = b.stake_address
        WHERE c.nft_name = ?
        ORDER BY c.timestamp ASC
    """
    cursor.execute(query, (nft_name,))
    all_comments_rows = cursor.fetchall()
    connection.close()

    comments_map = {row['comment_id']: dict(row) for row in all_comments_rows}
    for cid in comments_map:
        comments_map[cid]['replies'] = []

    nested_comments = []
    for cid, comment in comments_map.items():
        parent_id = comment.get('parent_comment_id')
        if parent_id in comments_map:
            comments_map[parent_id]['replies'].append(comment)
        else:
            nested_comments.append(comment)

    return jsonify(nested_comments)

@app.route('/tap_like', methods=['GET', 'POST'])
@login_required
def tap_like():
    nft_name = request.json.get('nft_name')
    action = int(request.json.get('action'))
    stake_address = request.json.get('stake_address')
    timestamp = request.json.get('timestamp')
    connection = sqlite3.connect("blocks.db")
    email_df = pd.DataFrame({"nft_name":nft_name, "stake_address":stake_address, "action":action, "timestamp":timestamp}, index=[0])
    email_df.to_sql("all_likes", connection, if_exists='append', index=False)

    cursor = connection.cursor()
    cursor.execute(f"UPDATE all_timeline SET like_count = like_count + {action} where nft_name = '{nft_name}'")

    connection.commit()
    connection.close()
    return json.dumps({"success":"ok"})

@app.route('/see_likes', methods=['GET', 'POST'])
@login_required
def see_likes():
    nft_name = request.json.get('nft_name')
    connection = sqlite3.connect("blocks.db")
    all_likes = pd.read_sql_query(f"SELECT stake_address FROM all_likes where nft_name = '{nft_name}' group by 1 HAVING sum(action)>0", connection)
    all_likes_json = all_likes.to_json(orient='records')
    connection.close()
    return json.dumps(all_likes_json)


@app.route('/address_likes', methods=['GET', 'POST'])
@login_required
def address_likes():
        '''Return the liked posts and comments by stake_address'''
        stake_address = request.json.get('stake_address')

        if not stake_address:
            return jsonify({'error': 'Missing required fields'}), 400

        connection = sqlite3.connect("blocks.db")
        all_likes = pd.read_sql_query(f"SELECT nft_name FROM all_likes where stake_address = '{stake_address}' group by 1 HAVING sum(action)>0", connection)
        all_comment_likes = pd.read_sql_query(f"SELECT comment_id FROM all_comment_likes where stake_address = '{stake_address}' group by 1 HAVING sum(action)>0", connection)
        all_likes_json = all_likes.to_json(orient='records')
        all_comment_likes_json = all_comment_likes.to_json(orient='records')
        connection.close()
        return json.dumps({'post_likes': all_likes_json, 'comment_likes': all_comment_likes_json})


@app.route('/view_comment_likes', methods=['POST'])
@login_required
def view_comment_likes():
        comment_id = request.json.get('comment_id')

        if not comment_id:
            return jsonify({'error': 'Missing required fields'}), 400

        connection = sqlite3.connect("blocks.db")
        all_comment_likes = pd.read_sql_query(f"SELECT stake_address FROM all_comment_likes where comment_id = '{comment_id}' group by 1 HAVING sum(action)>0", connection)
        all_comment_likes_json = all_comment_likes.to_json(orient='records')
        connection.close()
        return json.dumps(all_comment_likes_json)


@app.route('/set_comment_like', methods=['POST'])
@login_required
def set_comment_like():
    comment_id = request.json.get('comment_id')
    action = int(request.json.get('action'))
    stake_address = request.json.get('stake_address')
    timestamp = request.json.get('timestamp')
    connection = sqlite3.connect("blocks.db")
    email_df = pd.DataFrame({"comment_id":comment_id, "stake_address":stake_address, "action":action, "timestamp":timestamp}, index=[0])
    email_df.to_sql("all_comment_likes", connection, if_exists='append', index=False)
    cursor = connection.cursor()
    cursor.execute(f"UPDATE all_comments SET like_count = like_count + {action} where comment_id = '{comment_id}'")
    connection.commit()
    connection.close()
    return json.dumps({"success":"ok"})


@app.route('/share_bio', methods=['GET', 'POST'])
@login_required
def share_bio():
        bio_text = request.json.get('bio_text')
        user_name = request.json.get('user_name')
        stake_address = request.json.get('stake_address')
        timestamp = request.json.get('timestamp')
        connection = sqlite3.connect("blocks.db")
        bio_df = pd.DataFrame({"stake_address":stake_address, "bio_text":bio_text, "timestamp":timestamp, "user_name":user_name}, index=[0])
        bio_df.to_sql("all_bios", connection, if_exists='append', index=False)
        connection.close()
        return json.dumps({"success":"ok"})

@app.route('/see_bio', methods=['GET', 'POST'])
@login_required
def see_bio():
        stake_address = request.json.get('stake_address')
        connection = sqlite3.connect("blocks.db")
        all_bios = pd.read_sql_query(f"SELECT bio_text, user_name FROM all_bios where stake_address = '{stake_address}' ORDER BY timestamp DESC LIMIT 1", connection)
        all_bios_json = all_bios.to_json(orient='records')
        connection.close()
        return json.dumps(all_bios_json)

@app.route('/update_timeline', methods=['GET', 'POST'])
@login_required
def update_timeline():
    nft_name = request.json.get('nft_name')
    hide = int(request.json.get('hide'))
    grey = int(request.json.get('grey'))
    connection = sqlite3.connect("blocks.db")

    cursor = connection.cursor()
    print(f"UPDATE all_timeline SET hide = {hide}, grey = {grey} where nft_name = '{nft_name}'")
    cursor.execute(f"UPDATE all_timeline SET hide = {hide}, grey = {grey} where nft_name = '{nft_name}'")
    connection.commit()
    connection.close()
    return json.dumps({"success":"ok"})

@app.route('/tx_status', methods=['GET', 'POST'])
@login_required
def tx_status():
        nft_name = request.json.get('nft_name')
        txhash = request.json.get('txhash')
        connection = sqlite3.connect("blocks.db")
        am_hash = pd.read_sql_query(f"SELECT am_hash from all_timeline where nft_name = '{nft_name}'", connection)['am_hash'][0]
        cursor = connection.cursor()

        metadata = kp2.get_tx_metadata(txhash)
        if am_hash is not None and am_hash in str(metadata):
                policy_id = list(metadata[0]['metadata']['721'].keys())
                policy_id = [x for x in policy_id if x !='version'][0]
                asset_name = nft_name.encode("utf-8").hex()
                asset_info = kp2.get_asset_info(asset_name, policy_id)
                asset_id = asset_info["fingerprint"]
                return ({"success":policy_id +':'+ asset_id})
        else:
                return ({"success":"No moment found"})

        connection.commit()
        connection.close()


@app.route('/tap_follow', methods=['GET', 'POST'])
@login_required
def tap_follow():
        from_address = request.json.get('from_address')
        action = int(request.json.get('action'))
        to_address = request.json.get('to_address')
        timestamp = request.json.get('timestamp')
        connection = sqlite3.connect("blocks.db")

        email_df = pd.DataFrame({"from_address":from_address, "to_address":to_address, "action":action, "timestamp":timestamp}, index=[0])
        email_df.to_sql("all_follows", connection, if_exists='append', index=False)

        connection.commit()
        connection.close()
        return json.dumps({"success":"ok"})

@app.route('/see_follows', methods=['GET', 'POST'])
@login_required
def see_follows():
        from_address = request.json.get('from_address')
        connection = sqlite3.connect("blocks.db")
        all_likes = pd.read_sql_query(f"SELECT to_address, MAX(timestamp) as timestamp FROM all_follows where from_address = '{from_address}' group by 1 HAVING sum(action)>0", connection)
        all_likes_json = all_likes.to_json(orient='records')
        connection.close()
        return json.dumps(all_likes_json)

@app.route('/see_followers', methods=['GET', 'POST'])
@login_required
def see_followers():
        to_address = request.json.get('to_address')
        connection = sqlite3.connect("blocks.db")
        all_likes = pd.read_sql_query(f"SELECT from_address, MAX(timestamp) as timestamp FROM all_follows where to_address = '{to_address}' group by 1 HAVING sum(action)>0", connection)
        all_likes_json = all_likes.to_json(orient='records')
        connection.close()
        return json.dumps(all_likes_json)

@app.route('/register_notif', methods=['POST'])
@login_required
def register_notif():
        user_stake_addr = request.json.get('user_stake_addr')
        by_user = request.json.get('by_user')
        action = request.json.get('action')
        notification = request.json.get('notif')
        timestamp = request.json.get('timestamp')
        link = request.json.get('link')
        connection = sqlite3.connect("blocks.db")
        print('[register_notif]')
        if not user_stake_addr or not notification or not timestamp:
            return jsonify({'error': 'Missing required fields'}), 400

        if action not in ["like", "comment", "follow", "create"]:
            return jsonify({'error': 'Wrong notification type. Must be one of: "like", "follow", "comment", "create"'}), 400
        
        notif_id = str(uuid.uuid4())
        notif_df = pd.DataFrame({"id": notif_id, "user_stake_addr": user_stake_addr, "by_user": by_user, \
                "action": action, "notif": notification, "timestamp":timestamp, "link": link}, index=[0])
        notif_df.to_sql('notifications', connection, if_exists='append', index=False)
        connection.close()
        return jsonify({'status': 'success'}), 201


@app.route('/get_notif', methods=['POST'])
@login_required
def get_notif():
        user_stake_addr = request.json.get('user_stake_addr')
        print(f'[get_notif] user_stake_addr: {user_stake_addr}')
        connection = sqlite3.connect("blocks.db")
        if not user_stake_addr: 
            return jsonify({'error': 'Missing required fields'}), 400
        
        all_notifs = pd.read_sql_query(f'SELECT * FROM notifications WHERE user_stake_addr = ? ORDER BY timestamp DESC',\
                connection, params=(user_stake_addr,))
        all_notifs_json = all_notifs.to_json(orient='records')
        connection.close()
        return json.dumps(all_notifs_json)


@app.route('/upload_post_views', methods=['POST'])
@login_required
def upload_post_views():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() != 'csv':
        return jsonify({'error': 'Invalid file type'}), 400

    filename = re.sub(r'[^A-Za-z0-9._-]', '_', file.filename) 
    filepath = os.path.join(os.getcwd(), filename)

    try:
        file.save(filepath)
        df = pd.read_csv(filepath)

        # Filter out the stuff that's not a moment page
        first_col = df.columns[0]
        df[first_col] = df[first_col].astype(str).str.replace(r'^/m/', '', regex=True)
        df = df[df[first_col].astype(str).str.match(r'MOMENT-\d{4}-\d{2}-\d{2}-H\d+$')]

        # Drop second column - unique visitors. we only care about total views.
        if len(df.columns) > 1:
            df.drop(columns=[df.columns[1]], inplace=True)

        with sqlite3.connect("blocks.db") as conn:
            df.columns = ['nft_name', 'total_views']
            df.to_sql('moment_views', conn, if_exists='replace', index=False)

        if os.path.exists(filepath):
            os.remove(filepath)

        return jsonify({'status': 'success', 'rows_committed': len(df)}), 200

    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Processing error: {str(e)}'}), 400


@app.route('/get_post_views', methods=['POST'])
@login_required
def get_post_views():
    nft_name = request.json.get('nft_name')
    print(f'[/get_post_vies] nft_name: {nft_name}')
    if not nft_name:
        return jsonify({'status': 'Error: nft name not provided'}), 400

    connection = sqlite3.connect("blocks.db")
    moment_views = pd.read_sql_query(f'SELECT * FROM moment_views WHERE nft_name = ?',\
                connection, params=(nft_name,))
    moment_views_json = moment_views.to_json(orient='records')
    connection.close()
    return json.dumps(moment_views_json)


@app.route('/count_archive', methods=['POST'])
@login_required
def count_archive():
    archive = request.json.get('archive')
    print(f'[/count_archive] archive count requested for: {archive}')
    if not archive:
        return jsonify({'status': 'Error: nft name not provided'}), 400

    connection = sqlite3.connect("blocks.db")
    count_df = pd.read_sql_query(f'SELECT COUNT(*) FROM all_timeline WHERE archive = ? AND hide = 0 AND grey = 0',\
            connection, params=(archive,))
    count = int(count_df.iloc[0, 0])
    connection.close()
    return jsonify({'status': 'success', 'count': count}), 200


@app.route('/update_xp', methods=['POST'])
@login_required
def update_xp():
    stake_address = request.json.get('stake_address')
    xp_delta = request.json.get('xp_delta')
    if not stake_address or not xp_delta:
        return jsonify({'status': 'Error: missing fields'}), 400

    conn = sqlite3.connect("blocks.db")
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO user_xp (stake_address, xp)
        VALUES (?, ?)
        ON CONFLICT(stake_address) DO UPDATE SET xp = xp + ?
    """, (stake_address, xp_delta, xp_delta))
    conn.commit()
    cur.execute("SELECT xp FROM user_xp WHERE stake_address = ?", (stake_address,))
    xp = cur.fetchone()[0]
    conn.close()
    return jsonify({'stake_address': stake_address, 'xp': xp})


@app.route('/get_xp', methods=['POST'])
@login_required
def get_xp():
    stake_address = request.json.get('stake_address')
    if not stake_address:
        return jsonify({'status': 'Error: stake_address not provided'}), 400

    conn = sqlite3.connect("blocks.db")
    cur = conn.cursor()
    cur.execute("SELECT xp FROM user_xp WHERE stake_address = ?", (stake_address,))
    row = cur.fetchone()
    conn.close()
    if row:
        return jsonify({'stake_address': stake_address, 'xp': row[0]})
    else:
        return jsonify({'stake_address': stake_address, 'xp': 0})


# boilerplate flask app code
if __name__ == "__main__":
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
    app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024
    #app.run(host="0.0.0.0", port="4040", debug=True, ssl_context=('/etc/letsencrypt/live/api.thegoodnode.com/cert.pem', '/etc/letsencrypt/live/api.thegoodnode.com/privkey.pem'))
    app.run(host="0.0.0.0", port="4040", debug=True)
