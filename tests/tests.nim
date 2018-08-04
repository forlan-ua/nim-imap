import ospaths, asyncdispatch, net

import .. / nimap

const hostname = "imap.gmail.com"
const port = Port(993)

let username = getEnv("IMAP_GMAIL_USERNAME")
if username.len == 0:
    raise newException(ValueError, "Gmail username should been defined in the `IMAP_GMAIL_USERNAME` env variable")

let password = getEnv("IMAP_GMAIL_PASSWORD")
if password.len == 0:
    raise newException(ValueError, "Gmail password should been defined in the `IMAP_GMAIL_PASSWORD` env variable")


let sslContext = newContext(verifyMode=CVerifyNone)
let client = newAsyncImapClient(sslContext=sslContext)


block:
    echo "CONNECT"
    let resp = (waitFor client.connect(hostname, port))
    echo resp
    echo " "

block:
    echo "CAPABILITY"
    let resp = waitFor client.capability()
    echo resp
    echo " "

block:
    echo "LOGIN"
    let resp = waitFor client.login(username, password)
    echo resp
    echo " "

block:
    echo "SELECT"
    let resp = waitFor client.select("INBOX")
    echo resp
    echo " "

block:
    echo "EXAMINE"
    let resp = waitFor client.examine("INBOX")
    echo resp
    echo " "

block:
    echo "CREATE"
    let resp = waitFor client.create("testimap")
    echo resp
    echo " "

block:
    echo "RENAME"
    let resp = waitFor client.rename("testimap", "testimap2")
    echo resp
    echo " "

block:
    echo "DELETE"
    let resp = waitFor client.delete("testimap2")
    echo resp
    echo " "

block:
    echo "LIST"
    let resp = waitFor client.list()
    echo resp
    echo " "

block:
    echo "LOGOUT"
    let resp = waitFor client.logout()
    echo resp
    echo " "