import asyncnet, net, strutils
import imap
export imap
import asyncdispatch


const DEBUG = when defined(release): false else: true


type AsyncImapClient* = ImapClientBase[AsyncSocket]
type AsyncAuthenticationStep* = proc(res: string): Future[(string, AsyncAuthenticationStep)]


when defined(ssl):
    let defaultSslContext = newContext()
    proc newAsyncImapClient*(socket: AsyncSocket = nil, sslContext: SslContext = defaultSslContext): AsyncImapClient =
        var s = socket
        if s.isNil:
            s = newAsyncSocket()
        sslContext.wrapSocket(s)
        AsyncImapClient(socket: s)
else:
    proc newAsyncImapClient*(socket: AsyncSocket = nil): AsyncImapClient =
        var s = socket
        if s.isNil:
            s = newAsyncSocket()
        AsyncImapClient(socket: s)


proc getData(client: AsyncImapClient, tag: string = "*"): Future[RawResponse] {.async.} =
    result = @[]
    while true:
        let line = (await client.socket.recvLine()).strip()
        when DEBUG:
            echo "RESPONSE: ", line
        if client.checkLine(tag, line):
            break


proc send(client: AsyncImapClient, cmd: string): Future[RawResponse] {.async.} =
    let tag = client.genTag()
    let cmd = tag & " " & cmd & CRLF
    when DEBUG:
        echo "REQUEST: ", cmd.strip()
    await client.socket.send(cmd)
    result = await client.getData(tag)


proc connect*(client: AsyncImapClient, host: string, port: Port): Future[RawResponse] {.async.} =
    when DEBUG:
        echo "CONNECT"
    await client.socket.connect(host, port)
    result = await client.getData()


proc login*(client: AsyncImapClient, username, password: string): Future[RawResponse] {.async.} =
    result = await client.send("LOGIN " & username & " " & password)
    
    
proc capability*(client: AsyncImapClient): Future[RawResponse] {.async.} =
    result = await client.send("CAPABILITY")
    
    
proc starttls*(client: AsyncImapClient): Future[RawResponse] {.async.} =
    result = await client.send("STARTTLS")


proc noop*(client: AsyncImapClient): Future[RawResponse] {.async.} =
    result = await client.send("NOOP")
    
    
proc check*(client: AsyncImapClient): Future[RawResponse] {.async.} =
    result = await client.send("CHECK")
    
    
proc subscribe*(client: AsyncImapClient, mailbox: string): Future[RawResponse] {.async.} =
    result = await client.send("SUBSCRIBE " & mailbox)
    
    
proc unsubscribe*(client: AsyncImapClient, mailbox: string): Future[RawResponse] {.async.} =
    result = await client.send("UNSUBSCRIBE " & mailbox)


proc list*(client: AsyncImapClient, reference: string = "\"\"", mailbox: string = "\"*\""): Future[RawResponse] {.async.} =
    result = await client.send("LIST " & reference & " " & mailbox)


proc select*(client: AsyncImapClient, name: string): Future[RawResponse] {.async.} =
    result = await client.send("SELECT " & name)


proc examine*(client: AsyncImapClient, name: string): Future[RawResponse] {.async.} =
    result = await client.send("EXAMINE " & name)


proc status*(client: AsyncImapClient, name: string): Future[RawResponse] {.async.} =
    result = await client.send("STATUS " & name & " (MESSAGES)")


proc create*(client: AsyncImapClient, name: string): Future[RawResponse] {.async.} =
    result = await client.send("CREATE " & name)
    

proc rename*(client: AsyncImapClient, name: string): Future[RawResponse] {.async.} =
    result = await client.send("RENAME " & name)

    
proc delete*(client: AsyncImapClient, name: string): Future[RawResponse] {.async.} =
    result = await client.send("DELETE " & name)
    
        
proc expunge*(client: AsyncImapClient): Future[RawResponse] {.async.} =
    result = await client.send("EXPUNGE")


proc search*(client: AsyncImapClient, query: string): Future[RawResponse] {.async.} =
    result = await client.send("SEARCH " & query)


proc lsub*(client: AsyncImapClient, reference: string = "\"\"", mailbox: string = "\"*\""): Future[RawResponse] {.async.} =
    result = await client.send("LSUB " & reference & " " & mailbox)


proc fetch*(client: AsyncImapClient, mid: MessageId, item: string = "FULL"): Future[RawResponse] {.async.} =
    result = await client.send("FETCH " & mid & " " & item)
    
    
proc fetch*(client: AsyncImapClient, startmid, endmid: MessageId, item: string = "FULL"): Future[RawResponse] {.async.} =
    result = await client.send("FETCH " & startmid & ":" & endmid & " " & item)


proc store*(client: AsyncImapClient, mid: MessageId, item, value: string): Future[RawResponse] {.async.} =
    result = await client.send("STORE " & mid & " " & item & " " & value)


proc store*(client: AsyncImapClient, startmid, endmid: MessageId, item, value: string): Future[RawResponse] {.async.} =
    result = await client.send("STORE " & startmid & ":" & endmid & " " & item & " " & value)


proc copy*(client: AsyncImapClient, mid: MessageId, name: string): Future[RawResponse] {.async.} =
    result = await client.send("COPY " & mid & " " & name)
    

proc copy*(client: AsyncImapClient, startmid, endmid: MessageId, name: string): Future[RawResponse] {.async.} =
    result = await client.send("COPY " & startmid & ":" & endmid & " " & name)


proc close*(client: AsyncImapClient): Future[RawResponse] {.async.} =
    result = await client.send("CLOSE")


proc append*(client: AsyncImapClient, name, flags, msg: string): Future[RawResponse] {.async.} =
    var tag = client.genTag()
    when DEBUG:
        echo "REQUEST: ", tag & " " & " APPEND " & (if flags != "" : name & " (" & flags & ")" else: name) & " {" & $msg.len & "}"
    await client.socket.send(tag & " " & " APPEND " & (if flags != "" : name & " (" & flags & ")" else: name) & " {" & $msg.len & "}")

    let line = await client.socket.recvLine()
    when DEBUG:
        echo "RESPONSE: ", line

    if line.startsWith("+"):
        when DEBUG:
            echo "REQUEST: message body ", msg.len

        await client.socket.send(msg)
        result = await client.getData(tag)
    else:
        result = @[line]
        discard client.checkLine(tag, line)


proc authenticate*(client: AsyncImapClient, name: string, nextStep: AsyncAuthenticationStep): Future[RawResponse] {.async.} =
    var tag = client.genTag()

    var step = nextStep
    var req = tag & " AUTHENTICATE " & name
    
    while true:
        when DEBUG:
            echo "REQUEST: ", req
        await client.socket.send(req)

        let line = await client.socket.recvLine()
        when DEBUG:
            echo "RESPONSE: ", line
        if client.checkLine(tag, line):
            result = @[line]
            break

        (req, step) = await step(line)