import requests, base64, zlib, json
from urllib.parse import quote, unquote

BASEURL = "https://msg-api-rjpr.onrender.com"

def text2base64(text):
    return base64.b64encode(text.encode()).decode()

def compressencode(text):
    return base64.b64encode(zlib.compress(text.encode('utf-8'))).decode('utf-8')

def compressdecode(text64):
    return zlib.decompress(base64.b64decode(text64.encode('utf-8'))).decode('utf-8')

def msgidgen(sender_username, receiver_username):
    response = requests.post(f"{BASEURL}/transfer/nextid", json={"sender": sender_username, "receiver": receiver_username})
    if response.status_code == 200:
        return quote(compressencode(response.json()["id"]))
    return None

def sendmsg(msgid, sender_username, receiver_username, data):
    url = f"{BASEURL}/transfer/post/{msgid}"
    payload = {"data": quote(compressencode(data)), "sender": sender_username, "receiver": receiver_username}
    r = requests.post(url, json=payload)
    return r.status_code == 200, r.status_code, r.text

def getmsgsub(msgid):
    r = requests.get(f"{BASEURL}/transfer/get/{msgid}")
    return r.status_code == 200, r.status_code, r.text

def getmsg(msgid):
    ok, code, text = getmsgsub(msgid)
    if ok:
        try:
            data = compressdecode(unquote(json.loads(text)["data"]))
            return True, code, data
        except Exception as e:
            return False, code, f"decode error: {e}"
    return False, code, text

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
            mid = msgidgen(s, r)
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
