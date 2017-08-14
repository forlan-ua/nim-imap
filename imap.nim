import net, strutils


const CRLF* = "\c\L"
const DEBUG = when defined(release): false else: true


type ImapClientBase*[T] = ref object of RootObj
    socket*: T
    tag: int
type ImapClient* = ImapClientBase[Socket]
type RawResponse* = seq[string]
type MessageId* = string
type AuthenticationStep* = proc(res: string): (string, AuthenticationStep)


when defined(ssl):
    let defaultSslContext = newContext()
    proc newImapClient*(socket: Socket = nil, sslContext: SslContext = defaultSslContext): ImapClient =
        var s = socket
        if s.isNil:
            s = newSocket()
        sslContext.wrapSocket(s)
        ImapClient(socket: s)
else:
    proc newImapClient*(socket: Socket = nil): ImapClient =
        var s = socket
        if s.isNil:
            s = newSocket()
        ImapClient(socket: s)


proc genTag*(client: ImapClientBase): string =
    result = $client.tag
    client.tag.inc

proc checkLine*(client: ImapClientBase, tag,line: string): bool =
    result = false
    if line.startsWith(tag & " " & "OK"):
        result = true
    elif line.startsWith(tag & " " & "BAD"):
        result = true
    elif line.startsWith(tag & " " & "NO"):
        result = true


proc getData(client: ImapClient, tag: string = "*"): RawResponse =
    result = @[]
    while true:
        let line = client.socket.recvLine().strip()
        when DEBUG:
            echo "RESPONSE: ", line
        if client.checkLine(tag, line):
            break


proc send(client: ImapClient, cmd: string): RawResponse =
    let tag = client.genTag()
    let cmd = tag & " " & cmd & CRLF
    when DEBUG:
        echo "REQUEST: ", cmd.strip()
    client.socket.send(cmd)
    result = client.getData(tag)


proc connect*(client: ImapClient, host: string, port: Port): RawResponse =
    when DEBUG:
        echo "CONNECT"
    client.socket.connect(host, port)
    result = client.getData()


proc login*(client: ImapClient, username, password: string): RawResponse =
    result = client.send("LOGIN " & username & " " & password)
    
    
proc capability*(client: ImapClient): RawResponse =
    result = client.send("CAPABILITY")
    
    
proc starttls*(client: ImapClient): RawResponse =
    result = client.send("STARTTLS")


proc noop*(client: ImapClient): RawResponse =
    result = client.send("NOOP")
    
    
proc check*(client: ImapClient): RawResponse =
    result = client.send("CHECK")
    
    
proc subscribe*(client: ImapClient, mailbox: string): RawResponse =
    result = client.send("SUBSCRIBE " & mailbox)
    
    
proc unsubscribe*(client: ImapClient, mailbox: string): RawResponse =
    result = client.send("UNSUBSCRIBE " & mailbox)


proc list*(client: ImapClient, reference: string = "\"\"", mailbox: string = "\"*\""): RawResponse =
    result = client.send("LIST " & reference & " " & mailbox)


proc select*(client: ImapClient, name: string): RawResponse =
    result = client.send("SELECT " & name)


proc examine*(client: ImapClient, name: string): RawResponse =
    result = client.send("EXAMINE " & name)


proc status*(client: ImapClient, name: string): RawResponse =
    result = client.send("STATUS " & name & " (MESSAGES)")


proc create*(client: ImapClient, name: string): RawResponse =
    result = client.send("CREATE " & name)
    

proc rename*(client: ImapClient, name: string): RawResponse =
    result = client.send("RENAME " & name)

    
proc delete*(client: ImapClient, name: string): RawResponse =
    result = client.send("DELETE " & name)
    
        
proc expunge*(client: ImapClient): RawResponse =
    result = client.send("EXPUNGE")


proc search*(client: ImapClient, query: string): RawResponse =
    result = client.send("SEARCH " & query)


proc lsub*(client: ImapClient, reference: string = "\"\"", mailbox: string = "\"*\""): RawResponse =
    result = client.send("LSUB " & reference & " " & mailbox)


proc fetch*(client: ImapClient, mid: MessageId, item: string = "FULL"): RawResponse =
    result = client.send("FETCH " & mid & " " & item)
    
    
proc fetch*(client: ImapClient, startmid, endmid: MessageId, item: string = "FULL"): RawResponse =
    result = client.send("FETCH " & startmid & ":" & endmid & " " & item)


proc store*(client: ImapClient, mid: MessageId, item, value: string): RawResponse =
    result = client.send("STORE " & mid & " " & item & " " & value)


proc store*(client: ImapClient, startmid, endmid: MessageId, item, value: string): RawResponse =
    result = client.send("STORE " & startmid & ":" & endmid & " " & item & " " & value)


proc copy*(client: ImapClient, mid: MessageId, name: string): RawResponse =
    result = client.send("COPY " & mid & " " & name)
    

proc copy*(client: ImapClient, startmid, endmid: MessageId, name: string): RawResponse =
    result = client.send("COPY " & startmid & ":" & endmid & " " & name)


proc append*(client: ImapClient, name, flags, msg: string): RawResponse =
    var tag = client.genTag()
    when DEBUG:
        echo "REQUEST: ", tag & " " & " APPEND " & (if flags != "" : name & " (" & flags & ")" else: name) & " {" & $msg.len & "}"
    client.socket.send(tag & " " & " APPEND " & (if flags != "" : name & " (" & flags & ")" else: name) & " {" & $msg.len & "}")

    let line = client.socket.recvLine()
    when DEBUG:
        echo "RESPONSE: ", line

    if line.startsWith("+"):
        when DEBUG:
            echo "REQUEST: message body ", msg.len

        client.socket.send(msg)
        result = client.getData(tag)
    else:
        result = @[line]
        discard client.checkLine(tag, line)


proc authenticate*(client: ImapClient, name: string, nextStep: AuthenticationStep): RawResponse =
    var tag = client.genTag()

    var step = nextStep
    var req = tag & " AUTHENTICATE " & name
    
    while true:
        when DEBUG:
            echo "REQUEST: ", req
        client.socket.send(req)

        let line = client.socket.recvLine()
        when DEBUG:
            echo "RESPONSE: ", line
        if client.checkLine(tag, line):
            result = @[line]
            break

        (req, step) = step(line)