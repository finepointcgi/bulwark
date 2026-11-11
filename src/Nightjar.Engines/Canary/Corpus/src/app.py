import subprocess, hashlib, pickle, requests, yaml
def handler(user, cur, blob):
    subprocess.run("ls " + user, shell=True)
    subprocess.run(["ls", user])
    cur.execute("SELECT * FROM t WHERE name = '%s'" % user)
    cur.execute("SELECT * FROM t WHERE name = %s", (user,))
    pickle.loads(blob)
    yaml.load(blob)
    requests.get("https://x", verify=False)
    hashlib.md5(blob)
    hashlib.md5(blob, usedforsecurity=False)
