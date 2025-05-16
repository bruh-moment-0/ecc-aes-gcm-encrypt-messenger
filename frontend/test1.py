import requests, base64, zlib, json, hashlib
from urllib.parse import quote, unquote

BASEURL = "https://msg-api-w0oh.onrender.com"

def compressencode(text):
    return base64.b64encode(zlib.compress(text.encode())).decode()

def compressdecode(text64):
    return zlib.decompress(base64.b64decode(text64.encode())).decode()

def generate_msgid(sender_username, receiver_username):
    r1 = requests.post(f"{BASEURL}/user/get", json={"username": sender_username})
    r2 = requests.post(f"{BASEURL}/user/get", json={"username": receiver_username})
    if r1.status_code != 200 or r2.status_code != 200:
        return None
    sender_pk = json.loads(r1.text)["publickey"]
    receiver_pk = json.loads(r2.text)["publickey"]
    r = requests.post(f"{BASEURL}/transfer/nextid", json={"sender": sender_username, "receiver": receiver_username})
    if r.status_code != 200:
        return None
    msgid = r.json()["id"]
    return quote(msgid)

def sendmsg(msgid, sender_username, receiver_username, data):
    url = f"{BASEURL}/transfer/post/{msgid}"
    payload = {"data": quote(compressencode(data)), "sender": sender_username, "receiver": receiver_username}
    r = requests.post(url, json=payload)
    return r.status_code == 200, r.status_code, r.text

def getmsg(msgid):
    r = requests.get(f"{BASEURL}/transfer/get/{msgid}")
    if r.status_code != 200:
        return False, r.status_code, r.text
    try:
        data_encoded = json.loads(r.text)["data"]
        data = compressdecode(unquote(data_encoded))
        return True, r.status_code, data
    except Exception as e:
        return False, r.status_code, f"decode error: {e}"

def user_create(username, publickey, password):
    r = requests.post(f"{BASEURL}/user/create", json={"username": username, "publickey": publickey, "password": password})
    return r.status_code == 201, r.status_code, r.text

def user_get(username):
    r = requests.post(f"{BASEURL}/user/get", json={"username": username})
    return r.status_code == 200, r.status_code, r.text

def user_change(username, password, new_publickey):
    r = requests.post(f"{BASEURL}/user/change", json={"username": username, "password": password, "new_publickey": new_publickey})
    return r.status_code == 200, r.status_code, r.text

def user_remove(username, password):
    r = requests.post(f"{BASEURL}/user/remove", json={"username": username, "password": password})
    return r.status_code == 200, r.status_code, r.text

def menu():
    while True:
        print("\nSelect an option:")
        print("1) Create User")
        print("2) Get User Info")
        print("3) Change User Public Key")
        print("4) Remove User")
        print("5) Generate Message ID")
        print("6) Send Message")
        print("7) Get Message")
        print("0) Exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            u = input("Username: ")
            pkey = input("Public Key: ")
            pw = input("Password: ")
            ok, code, text = user_create(u, pkey, pw)
            print(f"Result: {ok}, Status: {code}, Response: {text}")
        elif choice == "2":
            u = input("Username: ")
            ok, code, text = user_get(u)
            print(f"Result: {ok}, Status: {code}, Response: {text}")
        elif choice == "3":
            u = input("Username: ")
            pw = input("Password: ")
            npkey = input("New Public Key: ")
            ok, code, text = user_change(u, pw, npkey)
            print(f"Result: {ok}, Status: {code}, Response: {text}")
        elif choice == "4":
            u = input("Username: ")
            pw = input("Password: ")
            ok, code, text = user_remove(u, pw)
            print(f"Result: {ok}, Status: {code}, Response: {text}")
        elif choice == "5":
            s = input("Sender Username: ")
            r = input("Receiver Username: ")
            mid = generate_msgid(s, r)
            print("Generated Message ID:", mid)
        elif choice == "6":
            mid = input("Message ID: ")
            s = input("Sender Username: ")
            r = input("Receiver Username: ")
            data = input("Message Data: ")
            ok, code, text = sendmsg(mid, s, r, data)
            print(f"Sent: {ok}, Status: {code}, Response: {text}")
        elif choice == "7":
            mid = input("Message ID: ")
            ok, code, data = getmsg(mid)
            if ok:
                print("Message:", data)
            else:
                print(f"Failed: {ok}, Status: {code}, Response: {data}")
        elif choice == "0":
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    menu()
