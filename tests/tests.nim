import ospaths, asyncdispatch

import .. / imap

const hostname = "imap.gmail.com"
const port = Port(993)

let username = getEnv("IMAP_GMAIL_USERNAME")
let password = getEnv("IMAP_GMAIL_PASSWORD")


let client = newAsyncImapClient()
echo "CONNECT"
echo (waitFor client.connect(hostname, port))
echo "CAPABILITY"
let resp = waitFor client.capability()

echo resp