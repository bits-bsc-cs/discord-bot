import os
import random
import asyncio
import re
import string
import discord
import json
import smtplib
import ssl
import sqlite3  # Import SQLite
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# Retrieve the secret and Parse it back into a JSON object
school_json_string = os.getenv('SCHOOL_JSON')
school_json = json.loads(school_json_string)

TOKEN = os.getenv('TOKEN')
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
port = 465  # For SSL

# Create a secure SSL context
context = ssl.create_default_context()
load_dotenv()
TOKEN = os.getenv('TOKEN')
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
client = discord.Client(fetch_offline_members=True)

client = discord.Client(fetch_offline_members=True)

validation_tokens = {}  # Store tokens awaiting validation
domain_role_map = {}  # Map email domains to discord roles
guild = None  # Variable to store the guild object

# SQLite connection
conn = sqlite3.connect("verified_users.db")
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS VerifiedUsers
             (user_id text PRIMARY KEY, email text, role_id integer, timestamp text)''')

@client.event
async def on_ready():
    global guild
    print(f'{client.user.name} has connected to Discord!')
    guilds = await client.fetch_guilds()
    guild = guilds[0]  # Get the first guild
    with open("schools.json", "r") as f:
        role_map_from_file = json.load(f)
    
    actual_roles = await guild.fetch_roles()
    for domain, role_name in role_map_from_file.items():
        for actual_role in actual_roles:
            if actual_role.name == role_name:
                domain_role_map[domain] = actual_role
                break
        else:  # Role not found
            print("Could not find matching role for "+str(role_name))

@client.event
async def on_member_join(member):
    await member.create_dm()
    await member.dm_channel.send(
        f'Send me your .edu email address to get a role in {guild.name}'
    )

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    if message.channel != message.author.dm_channel:
        return

    if message.content.startswith("token_"):  # Check for token prefix
        split = message.content.split("_")
        if len(split) == 2 and split[0] == "token":  # Correct token format
            await check_token_and_give_role(message.author, split[1])
            return
    else:
        await parse_email_message(message)
        return

    await message.author.dm_channel.send("Bad message")

def randomString(stringLength=40):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(stringLength))

def get_role_for_domain(domain):
    return domain_role_map.get(domain)

async def check_token_and_give_role(user, token):
    if user.id not in validation_tokens:
        await user.dm_channel.send("No awaiting validation")
        return

    validation = validation_tokens[user.id]
    if validation[0] == token:  # Valid token
        member = guild.get_member(user.id)
        if member:
            await member.add_roles(validation[1])
            await user.dm_channel.send("done")
            # Store user data in SQLite
            c.execute("INSERT OR REPLACE INTO VerifiedUsers VALUES (?, ?, ?, ?)", (user.id, validation[2], validation[1].id, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            del validation_tokens[user.id]
        else:
            await user.dm_channel.send("failed. message admins")
    else:
        await user.dm_channel.send("bad token")

async def parse_email_message(message):
    if message.author.id in validation_tokens:
        expire = validation_tokens[message.author.id][2]
        if datetime.now() > expire:
            del validation_tokens[message.author.id]
        else:
            await message.author.dm_channel.send("We already sent you an email! Wait 1hr.")
            return

    for domain, role_name in school_json.items():
        if domain in message.content:  # Match domain from the secret
            email_regex = re.compile(f"^[A-Za-z0-9\.\-\_]+@{domain}$")
            if email_regex.match(message.content):
                role = get_role_for_domain(domain)
                if role:
                    random_token = randomString()
                    validation_tokens[message.author.id] = (random_token, role, message.content)
                    send_email(message.content, f"Subject: Discord Bot .edu Email Verification\n\nPlease reply to the discord bot with the following:\ntoken_{random_token}")
                    await message.author.dm_channel.send("Check your email.")
                else:
                    await message.author.dm_channel.send("Role not found for this domain. Message admins for help.")
                return

    await message.author.dm_channel.send("Invalid email")

def send_email(address, body):
    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, address, body)

client.run(TOKEN)