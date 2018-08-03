# https://tools.ietf.org/html/rfc3501

import asyncnet, net, asyncdispatch, strutils
export Port


const CRLF* = "\c\L"
const DEBUG = when defined(release): false else: true


type ImapClientBase*[SocketType] = ref object of RootObj
    socket*: SocketType
    tag: int

type ImapClient* = ImapClientBase[Socket]
type AsyncImapClient* = ImapClientBase[AsyncSocket]

type RawResponse* = seq[string]
type MessageId* = string
type AuthenticationStep* = proc(res: string): (string, AuthenticationStep)


when defined(ssl):
    let defaultSslContext* = newContext(verifyMode=CVerifyNone)
    proc newImapClient*(socket: Socket = nil, sslContext: SslContext = defaultSslContext): ImapClient =
        var s = socket
        if s.isNil:
            s = newSocket()
        if not sslContext.isNil:
            sslContext.wrapSocket(s)
        ImapClient(socket: s)

    proc newAsyncImapClient*(socket: AsyncSocket = nil, sslContext: SslContext = defaultSslContext): AsyncImapClient =
        var s = socket
        if s.isNil:
            s = newAsyncSocket()
        if not sslContext.isNil:
            sslContext.wrapSocket(s)
        AsyncImapClient(socket: s)
else:
    proc newImapClient*(socket: Socket = nil): ImapClient =
        var s = socket
        if s.isNil:
            s = newSocket()
        ImapClient(socket: s)

    proc newAsyncImapClient*(socket: AsyncSocket = nil): AsyncImapClient =
        var s = socket
        if s.isNil:
            s = newAsyncSocket()
        AsyncImapClient(socket: s)


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


proc getData*(client: ImapClient | AsyncImapClient, tag: string = "*"): Future[RawResponse] {.multisync.} =
    result = @[]
    while true:
        var line = (await client.socket.recvLine()).strip()
        if line.len > 0:
            echo "LINE: ", line
            result.add(line)
        if client.checkLine(tag, line):
            break


proc send(client: ImapClient | AsyncImapClient, cmd: string): Future[RawResponse] {.multisync.} =
    let tag = client.genTag()
    let cmd = tag & " " & cmd & CRLF

    echo "CMD: ", cmd

    await client.socket.send(cmd)
    result = await client.getData(tag)


proc connect*(client: ImapClient | AsyncImapClient, host: string, port: Port): Future[RawResponse] {.multisync.} =
    await client.socket.connect(host, port)
    result = await client.getData()


proc login*(client: ImapClient | AsyncImapClient, username, password: string): Future[RawResponse] {.multisync.} =
    result = await client.send("LOGIN " & username & " " & password)
    
    
proc capability*(client: ImapClient | AsyncImapClient): Future[RawResponse] {.multisync.} =
    ## The CAPABILITY command requests a listing of capabilities that the
    ## server supports.  The server MUST send a single untagged
    ## CAPABILITY response with "IMAP4rev1" as one of the listed
    ## capabilities before the (tagged) OK response.
    ## 
    ## A capability name which begins with "AUTH=" indicates that the
    ## server supports that particular authentication mechanism.  All
    ## such names are, by definition, part of this specification.  For
    ## example, the authorization capability for an experimental
    ## "blurdybloop" authenticator would be "AUTH=XBLURDYBLOOP" and not
    ## "XAUTH=BLURDYBLOOP" or "XAUTH=XBLURDYBLOOP".
    ##
    ## Other capability names refer to extensions, revisions, or
    ## amendments to this specification.  See the documentation of the
    ## CAPABILITY response for additional information.  No capabilities,
    ## beyond the base IMAP4rev1 set defined in this specification, are
    ## enabled without explicit client action to invoke the capability.
    ##
    ## Client and server implementations MUST implement the STARTTLS,
    ## LOGINDISABLED, and AUTH=PLAIN (described in [IMAP-TLS])
    ## capabilities.  See the Security Considerations section for
    ## important information.
    ##
    ## See the section entitled "Client Commands -
    ## Experimental/Expansion" for information about the form of site or
    ## implementation-specific capabilities.

    result = await client.send("CAPABILITY")
    
    
proc starttls*(client: ImapClient | AsyncImapClient): Future[RawResponse] {.multisync.} =
    ## A [TLS] negotiation begins immediately after the CRLF at the end
    ## of the tagged OK response from the server.  Once a client issues a
    ## STARTTLS command, it MUST NOT issue further commands until a
    ## server response is seen and the [TLS] negotiation is complete.
    ##
    ## The server remains in the non-authenticated state, even if client
    ## credentials are supplied during the [TLS] negotiation.  This does
    ## not preclude an authentication mechanism such as EXTERNAL (defined
    ## in [SASL]) from using client identity determined by the [TLS]
    ## negotiation.
    ##
    ## Once [TLS] has been started, the client MUST discard cached
    ## information about server capabilities and SHOULD re-issue the
    ## CAPABILITY command.  This is necessary to protect against man-in-
    ## the-middle attacks which alter the capabilities list prior to
    ## STARTTLS.  The server MAY advertise different capabilities after
    ## STARTTLS.

    result = await client.send("STARTTLS")


proc noop*(client: ImapClient | AsyncImapClient): Future[RawResponse] {.multisync.} =
    ## The NOOP command always succeeds.  It does nothing.
    ## 
    ## Since any command can return a status update as untagged data, the
    ## NOOP command can be used as a periodic poll for new messages or
    ## message status updates during a period of inactivity (this is the
    ## preferred method to do this).  The NOOP command can also be used
    ## to reset any inactivity autologout timer on the server.

    result = await client.send("NOOP")


proc logout*(client: ImapClient | AsyncImapClient): Future[RawResponse] {.multisync.} =
    ## The LOGOUT command informs the server that the client is done with
    ## the connection.  The server MUST send a BYE untagged response
    ## before the (tagged) OK response, and then close the network
    ## connection.

    result = await client.send("LOGOUT")
    
    
proc check*(client: ImapClient | AsyncImapClient): Future[RawResponse] {.multisync.} =
    result = await client.send("CHECK")
    
    
proc subscribe*(client: ImapClient | AsyncImapClient, mailbox: string): Future[RawResponse] {.multisync.} =
    result = await client.send("SUBSCRIBE " & mailbox)
    
    
proc unsubscribe*(client: ImapClient | AsyncImapClient, mailbox: string): Future[RawResponse] {.multisync.} =
    result = await client.send("UNSUBSCRIBE " & mailbox)


proc list*(client: ImapClient | AsyncImapClient, reference: string = "\"\"", mailbox: string = "\"*\""): Future[RawResponse] {.multisync.} =
    result = await client.send("LIST " & reference & " " & mailbox)


proc select*(client: ImapClient | AsyncImapClient, name: string): Future[RawResponse] {.multisync.} =
    result = await client.send("SELECT " & name)


proc examine*(client: ImapClient | AsyncImapClient, name: string): Future[RawResponse] {.multisync.} =
    result = await client.send("EXAMINE " & name)


proc status*(client: ImapClient | AsyncImapClient, name: string): Future[RawResponse] {.multisync.} =
    result = await client.send("STATUS " & name & " (MESSAGES)")


proc create*(client: ImapClient | AsyncImapClient, name: string): Future[RawResponse] {.multisync.} =
    result = await client.send("CREATE " & name)
    

proc rename*(client: ImapClient | AsyncImapClient, name: string): Future[RawResponse] {.multisync.} =
    result = await client.send("RENAME " & name)

    
proc delete*(client: ImapClient | AsyncImapClient, name: string): Future[RawResponse] {.multisync.} =
    result = await client.send("DELETE " & name)
    
        
proc expunge*(client: ImapClient | AsyncImapClient): Future[RawResponse] {.multisync.} =
    result = await client.send("EXPUNGE")


proc search*(client: ImapClient | AsyncImapClient, query: string): Future[RawResponse] {.multisync.} =
    result = await client.send("SEARCH " & query)


proc lsub*(client: ImapClient | AsyncImapClient, reference: string = "\"\"", mailbox: string = "\"*\""): Future[RawResponse] {.multisync.} =
    result = await client.send("LSUB " & reference & " " & mailbox)


proc fetch*(client: ImapClient | AsyncImapClient, mid: MessageId, item: string = "FULL"): Future[RawResponse] {.multisync.} =
    result = await client.send("FETCH " & mid & " " & item)
    
    
proc fetch*(client: ImapClient | AsyncImapClient, startmid, endmid: MessageId, item: string = "FULL"): Future[RawResponse] {.multisync.} =
    result = await client.send("FETCH " & startmid & ":" & endmid & " " & item)


proc store*(client: ImapClient | AsyncImapClient, mid: MessageId, item, value: string): Future[RawResponse] {.multisync.} =
    result = await client.send("STORE " & mid & " " & item & " " & value)


proc store*(client: ImapClient | AsyncImapClient, startmid, endmid: MessageId, item, value: string): Future[RawResponse] {.multisync.} =
    result = await client.send("STORE " & startmid & ":" & endmid & " " & item & " " & value)


proc copy*(client: ImapClient | AsyncImapClient, mid: MessageId, name: string): Future[RawResponse] {.multisync.} =
    result = await client.send("COPY " & mid & " " & name)
    

proc copy*(client: ImapClient | AsyncImapClient, startmid, endmid: MessageId, name: string): Future[RawResponse] {.multisync.} =
    result = await client.send("COPY " & startmid & ":" & endmid & " " & name)


proc append*(client: ImapClient | AsyncImapClient, name, flags, msg: string): Future[RawResponse] {.multisync.} =
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


proc authenticate*(client: ImapClient | AsyncImapClient, name: string, nextStep: AuthenticationStep): Future[RawResponse] {.multisync.} =
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

        (req, step) = step(line)