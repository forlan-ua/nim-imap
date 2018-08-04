## https://tools.ietf.org/html/rfc3501

import net, asyncnet, asyncdispatch, strutils, tables
export Port


const CRLF* = "\c\L"


type ImapCommandStatus* = enum
    icsContinue = -1, icsOk, icsBad, icsNo


type ImapListener = proc(line: string)


type ImapClientBase*[SocketType] = ref object of RootObj
    socket*: SocketType
    ssl: bool
    tag: int

type ImapClient* = ImapClientBase[Socket]
type AsyncImapClient* = ImapClientBase[AsyncSocket]


proc newImapClient*(): ImapClient =
    ImapClient(socket: newSocket())


proc newAsyncImapClient*(): AsyncImapClient =
    AsyncImapClient(socket: newAsyncSocket())


when defined(ssl):
    proc newImapClient*(sslContext: SslContext): ImapClient =
        let s = newSocket()
        sslContext.wrapSocket(s)
        ImapClient(socket: s, ssl: true)


    proc newAsyncImapClient*( sslContext: SslContext): AsyncImapClient =
        let s = newAsyncSocket()
        sslContext.wrapSocket(s)
        AsyncImapClient(socket: s, ssl: true)


proc ssl*(client: ImapClientBase): bool = 
    client.ssl


proc checkLine(client: ImapClientBase, tag, line: string): ImapCommandStatus =
    result = icsContinue

    var ind = 0
    while ind < tag.len:
        if tag[ind] != line[ind]:
            return
        ind.inc
    ind.inc

    case line[ind]:
        of 'O':
            if line[ind + 1] == 'K':
                result = icsOk
        of 'B':
            if line[ind + 1] == 'A' and line[ind + 2] == 'D':
                result = icsBad
        of 'N':
            if line[ind + 1] == 'O':
                result = icsNo
        else:
            discard


proc genTag(client: ImapClientBase): string =
    result = $client.tag
    client.tag.inc


proc getData(client: ImapClient | AsyncImapClient, tag: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync.} =
    while true:
        var line = (await client.socket.recvLine()).strip()
        result = client.checkLine(tag, line)

        when defined(debugImap):
            echo "IMAP GOT LINE: ", line

        if line.len > 0:
            if not listener.isNil:
                listener(line)

        if result != icsContinue:
            break


proc send(client: ImapClient | AsyncImapClient, cmd: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync.} =
    let tag = client.genTag()
    let cmd = tag & " " & cmd & CRLF

    when defined(debugImap):
        echo "SEND CMD: ", cmd

    await client.socket.send(cmd)
    result = await client.getData(tag, listener)


proc connect*(client: ImapClient | AsyncImapClient, host: string, port: Port, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    await client.socket.connect(host, port)
    result = await client.getData("*", listener)
    
    
proc capability*(client: ImapClient | AsyncImapClient, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.1.1.  CAPABILITY Command
    ##
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

    result = await client.send("CAPABILITY", listener)


proc noop*(client: ImapClient | AsyncImapClient, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.1.2.  NOOP Command
    ##
    ## The NOOP command always succeeds.  It does nothing.
    ## 
    ## Since any command can return a status update as untagged data, the
    ## NOOP command can be used as a periodic poll for new messages or
    ## message status updates during a period of inactivity (this is the
    ## preferred method to do this).  The NOOP command can also be used
    ## to reset any inactivity autologout timer on the server.

    result = await client.send("NOOP", listener)


proc logout*(client: ImapClient | AsyncImapClient, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.1.3.  LOGOUT Command
    ##
    ## The LOGOUT command informs the server that the client is done with
    ## the connection.  The server MUST send a BYE untagged response
    ## before the (tagged) OK response, and then close the network
    ## connection.

    result = await client.send("LOGOUT", listener)
    
    
proc starttls*(client: ImapClient | AsyncImapClient, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.2.1.  STARTTLS Command
    ##
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

    result = await client.send("STARTTLS", listener)


proc authenticate*(client: ImapClient | AsyncImapClient, mechanism, data: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.2.2.  AUTHENTICATE Command
    ##
    ## The AUTHENTICATE command indicates a [SASL] authentication
    ## mechanism to the server.  If the server supports the requested
    ## authentication mechanism, it performs an authentication protocol
    ## exchange to authenticate and identify the client.  It MAY also
    ## negotiate an OPTIONAL security layer for subsequent protocol
    ## interactions.  If the requested authentication mechanism is not
    ## supported, the server SHOULD reject the AUTHENTICATE command by
    ## sending a tagged NO response.
    ##
    ## The AUTHENTICATE command does not support the optional "initial
    ## response" feature of [SASL].  Section 5.1 of [SASL] specifies how
    ## to handle an authentication mechanism which uses an initial
    ## response.
    ##
    ## The service name specified by this protocol's profile of [SASL] is
    ## "imap".
    ##
    ## The authentication protocol exchange consists of a series of
    ## server challenges and client responses that are specific to the
    ## authentication mechanism.  A server challenge consists of a
    ## command continuation request response with the "+" token followed
    ## by a BASE64 encoded string.  The client response consists of a
    ## single line consisting of a BASE64 encoded string.  If the client
    ## wishes to cancel an authentication exchange, it issues a line
    ## consisting of a single "*".  If the server receives such a
    ## response, it MUST reject the AUTHENTICATE command by sending a
    ## tagged BAD response.
    ##
    ## If a security layer is negotiated through the [SASL]
    ## authentication exchange, it takes effect immediately following the
    ## CRLF that concludes the authentication exchange for the client,
    ## and the CRLF of the tagged OK response for the server.
    ##
    ## While client and server implementations MUST implement the
    ## AUTHENTICATE command itself, it is not required to implement any
    ## authentication mechanisms other than the PLAIN mechanism described
    ## in [IMAP-TLS].  Also, an authentication mechanism is not required
    ## to support any security layers.
    ##
    ##     Note: a server implementation MUST implement a
    ##     configuration in which it does NOT permit any plaintext
    ##     password mechanisms, unless either the STARTTLS command
    ##     has been negotiated or some other mechanism that
    ##     protects the session from password snooping has been
    ##     provided.  Server sites SHOULD NOT use any configuration
    ##     which permits a plaintext password mechanism without
    ##     such a protection mechanism against password snooping.
    ##     Client and server implementations SHOULD implement
    ##     additional [SASL] mechanisms that do not use plaintext
    ##     passwords, such the GSSAPI mechanism described in [SASL]
    ##     and/or the [DIGEST-MD5] mechanism.
    ##
    ## Servers and clients can support multiple authentication
    ## mechanisms.  The server SHOULD list its supported authentication
    ## mechanisms in the response to the CAPABILITY command so that the
    ## client knows which authentication mechanisms to use.
    ##
    ## A server MAY include a CAPABILITY response code in the tagged OK
    ## response of a successful AUTHENTICATE command in order to send
    ## capabilities automatically.  It is unnecessary for a client to
    ## send a separate CAPABILITY command if it recognizes these
    ## automatic capabilities.  This should only be done if a security
    ## layer was not negotiated by the AUTHENTICATE command, because the
    ## tagged OK response as part of an AUTHENTICATE command is not
    ## protected by encryption/integrity checking.  [SASL] requires the
    ## client to re-issue a CAPABILITY command in this case.
    ##
    ## If an AUTHENTICATE command fails with a NO response, the client
    ## MAY try another authentication mechanism by issuing another
    ## AUTHENTICATE command.  It MAY also attempt to authenticate by
    ## using the LOGIN command (see section 6.2.3 for more detail).  In
    ## other words, the client MAY request authentication types in
    ## decreasing order of preference, with the LOGIN command as a last
    ## resort.
    ##
    ## The authorization identity passed from the client to the server
    ## during the authentication exchange is interpreted by the server as
    ## the user name whose privileges the client is requesting.

    var cmd = "AUTHENTICATE " & mechanism
    if data.len > 0:
        cmd &= " " & data
    result = await client.send(cmd, listener)


proc login*(client: ImapClient | AsyncImapClient, username, password: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.2.3.  LOGIN Command
    ##
    ## The LOGIN command identifies the client to the server and carries
    ## the plaintext password authenticating this user.
    ## 
    ## A server MAY include a CAPABILITY response code in the tagged OK
    ## response to a successful LOGIN command in order to send
    ## capabilities automatically.  It is unnecessary for a client to
    ## send a separate CAPABILITY command if it recognizes these
    ## automatic capabilities.
    ##
    ## Note: Use of the LOGIN command over an insecure network
    ## (such as the Internet) is a security risk, because anyone
    ## monitoring network traffic can obtain plaintext passwords.
    ## The LOGIN command SHOULD NOT be used except as a last
    ## resort, and it is recommended that client implementations
    ## have a means to disable any automatic use of the LOGIN
    ## command.
    ##
    ## Unless either the STARTTLS command has been negotiated or
    ## some other mechanism that protects the session from
    ## password snooping has been provided, a server
    ## implementation MUST implement a configuration in which it
    ## advertises the LOGINDISABLED capability and does NOT permit
    ## the LOGIN command.  Server sites SHOULD NOT use any
    ## configuration which permits the LOGIN command without such
    ## a protection mechanism against password snooping.  A client
    ## implementation MUST NOT send a LOGIN command if the
    ## LOGINDISABLED capability is advertised.

    result = await client.send("LOGIN " & username & " " & password, listener)


proc select*(client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.1.  SELECT Command
    ##
    ## The SELECT command selects a mailbox so that messages in the
    ## mailbox can be accessed.  Before returning an OK to the client,
    ## the server MUST send the following untagged data to the client.
    ## Note that earlier versions of this protocol only required the
    ## FLAGS, EXISTS, and RECENT untagged data; consequently, client
    ## implementations SHOULD implement default behavior for missing data
    ## as discussed with the individual item.
    ##
    ## Only one mailbox can be selected at a time in a connection;
    ## simultaneous access to multiple mailboxes requires multiple
    ## connections.  The SELECT command automatically deselects any
    ## currently selected mailbox before attempting the new selection.
    ## Consequently, if a mailbox is selected and a SELECT command that
    ## fails is attempted, no mailbox is selected.
    ## 
    ## If the client is permitted to modify the mailbox, the server
    ## SHOULD prefix the text of the tagged OK response with the
    ## "[READ-WRITE]" response code.
    ##
    ## If the client is not permitted to modify the mailbox but is
    ## permitted read access, the mailbox is selected as read-only, and
    ## the server MUST prefix the text of the tagged OK response to
    ## SELECT with the "[READ-ONLY]" response code.  Read-only access
    ## through SELECT differs from the EXAMINE command in that certain
    ## read-only mailboxes MAY permit the change of permanent state on a
    ## per-user (as opposed to global) basis.  Netnews messages marked in
    ## a server-based .newsrc file are an example of such per-user
    ## permanent state that can be modified with read-only mailboxes.

    result = await client.send("SELECT " & mailbox, listener)


proc examine*(client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.2.  EXAMINE Command
    ##
    ## The EXAMINE command is identical to SELECT and returns the same
    ## output; however, the selected mailbox is identified as read-only.
    ## No changes to the permanent state of the mailbox, including
    ## per-user state, are permitted; in particular, EXAMINE MUST NOT
    ## cause messages to lose the \Recent flag.
    ##
    ## The text of the tagged OK response to the EXAMINE command MUST
    ## begin with the "[READ-ONLY]" response code.
    
    result = await client.send("EXAMINE " & mailbox, listener)


proc create*(client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.3.  CREATE Command
    ##
    ## The CREATE command creates a mailbox with the given name.  An OK
    ## response is returned only if a new mailbox with that name has been
    ## created.  It is an error to attempt to create INBOX or a mailbox
    ## with a name that refers to an extant mailbox.  Any error in
    ## creation will return a tagged NO response.
    ##
    ## If the mailbox name is suffixed with the server's hierarchy
    ## separator character (as returned from the server by a LIST
    ## command), this is a declaration that the client intends to create
    ## mailbox names under this name in the hierarchy.  Server
    ## implementations that do not require this declaration MUST ignore
    ## the declaration.  In any case, the name created is without the
    ## trailing hierarchy delimiter.
    ##
    ## If the server's hierarchy separator character appears elsewhere in
    ## the name, the server SHOULD create any superior hierarchical names
    ## that are needed for the CREATE command to be successfully
    ## completed.  In other words, an attempt to create "foo/bar/zap" on
    ## a server in which "/" is the hierarchy separator character SHOULD
    ## create foo/ and foo/bar/ if they do not already exist.
    ##
    ## If a new mailbox is created with the same name as a mailbox which
    ## was deleted, its unique identifiers MUST be greater than any
    ## unique identifiers used in the previous incarnation of the mailbox
    ## UNLESS the new incarnation has a different unique identifier
    ## validity value.  See the description of the UID command for more
    ## detail.
    ##
    ##     Note: The interpretation of this example depends on whether
    ##     "/" was returned as the hierarchy separator from LIST.  If
    ##     "/" is the hierarchy separator, a new level of hierarchy
    ##     named "owatagusiam" with a member called "blurdybloop" is
    ##     created.  Otherwise, two mailboxes at the same hierarchy
    ##     level are created.
    
    result = await client.send("CREATE " & mailbox, listener)

    
proc delete*(client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.4.  DELETE Command
    ##
    ## The DELETE command permanently removes the mailbox with the given
    ## name.  A tagged OK response is returned only if the mailbox has
    ## been deleted.  It is an error to attempt to delete INBOX or a
    ## mailbox name that does not exist.
    ##
    ## The DELETE command MUST NOT remove inferior hierarchical names.
    ## For example, if a mailbox "foo" has an inferior "foo.bar"
    ## (assuming "." is the hierarchy delimiter character), removing
    ## "foo" MUST NOT remove "foo.bar".  It is an error to attempt to
    ## delete a name that has inferior hierarchical names and also has
    ## the \Noselect mailbox name attribute (see the description of the
    ## LIST response for more details).
    ##
    ## It is permitted to delete a name that has inferior hierarchical
    ## names and does not have the \Noselect mailbox name attribute.  In
    ## this case, all messages in that mailbox are removed, and the name
    ## will acquire the \Noselect mailbox name attribute.
    ##
    ## The value of the highest-used unique identifier of the deleted
    ## mailbox MUST be preserved so that a new mailbox created with the
    ## same name will not reuse the identifiers of the former
    ## incarnation, UNLESS the new incarnation has a different unique
    ## identifier validity value.  See the description of the UID command
    ## for more detail.
    
    result = await client.send("DELETE " & mailbox, listener)
    

proc rename*(client: ImapClient | AsyncImapClient, oldname, newname: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.5.  RENAME Command
    ##
    ## The RENAME command changes the name of a mailbox.  A tagged OK
    ## response is returned only if the mailbox has been renamed.  It is
    ## an error to attempt to rename from a mailbox name that does not
    ## exist or to a mailbox name that already exists.  Any error in
    ## renaming will return a tagged NO response.
    ##
    ## If the name has inferior hierarchical names, then the inferior
    ## hierarchical names MUST also be renamed.  For example, a rename of
    ## "foo" to "zap" will rename "foo/bar" (assuming "/" is the
    ## hierarchy delimiter character) to "zap/bar".
    ##
    ## If the server's hierarchy separator character appears in the name,
    ## the server SHOULD create any superior hierarchical names that are
    ## needed for the RENAME command to complete successfully.  In other
    ## words, an attempt to rename "foo/bar/zap" to baz/rag/zowie on a
    ## server in which "/" is the hierarchy separator character SHOULD
    ## create baz/ and baz/rag/ if they do not already exist.
    ##
    ## The value of the highest-used unique identifier of the old mailbox
    ## name MUST be preserved so that a new mailbox created with the same
    ## name will not reuse the identifiers of the former incarnation,
    ## UNLESS the new incarnation has a different unique identifier
    ## validity value.  See the description of the UID command for more
    ## detail.
    ##
    ## Renaming INBOX is permitted, and has special behavior.  It moves
    ## all messages in INBOX to a new mailbox with the given name,
    ## leaving INBOX empty.  If the server implementation supports
    ## inferior hierarchical names of INBOX, these are unaffected by a
    ## rename of INBOX.
    
    result = await client.send("RENAME " & oldname & " " & newname, listener)
    
    
proc subscribe*(client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.6.  SUBSCRIBE Command
    ##
    ## The SUBSCRIBE command adds the specified mailbox name to the
    ## server's set of "active" or "subscribed" mailboxes as returned by
    ## the LSUB command.  This command returns a tagged OK response only
    ## if the subscription is successful.
    ##
    ## A server MAY validate the mailbox argument to SUBSCRIBE to verify
    ## that it exists.  However, it MUST NOT unilaterally remove an
    ## existing mailbox name from the subscription list even if a mailbox
    ## by that name no longer exists.
    ##
    ##     Note: This requirement is because a server site can
    ##     choose to routinely remove a mailbox with a well-known
    ##     name (e.g., "system-alerts") after its contents expire,
    ##     with the intention of recreating it when new contents
    ##     are appropriate.

    result = await client.send("SUBSCRIBE " & mailbox, listener)
    
    
proc unsubscribe*(client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.7.  UNSUBSCRIBE Command
    ##
    ## The UNSUBSCRIBE command removes the specified mailbox name from
    ## the server's set of "active" or "subscribed" mailboxes as returned
    ## by the LSUB command.  This command returns a tagged OK response
    ## only if the unsubscription is successful.

    result = await client.send("UNSUBSCRIBE " & mailbox, listener)


proc list*(client: ImapClient | AsyncImapClient, reference: string = "\"\"", mailbox: string = "\"*\"", listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.8.  LIST Command
    ##
    ## The LIST command returns a subset of names from the complete set
    ## of all names available to the client.  Zero or more untagged LIST
    ## replies are returned, containing the name attributes, hierarchy
    ## delimiter, and name; see the description of the LIST reply for
    ## more detail.
    ##
    ## The LIST command SHOULD return its data quickly, without undue
    ## delay.  For example, it SHOULD NOT go to excess trouble to
    ## calculate the \Marked or \Unmarked status or perform other
    ## processing; if each name requires 1 second of processing, then a
    ## list of 1200 names would take 20 minutes!
    ##
    ## An empty ("" string) reference name argument indicates that the
    ## mailbox name is interpreted as by SELECT.  The returned mailbox
    ## names MUST match the supplied mailbox name pattern.  A non-empty
    ## reference name argument is the name of a mailbox or a level of
    ## mailbox hierarchy, and indicates the context in which the mailbox
    ## name is interpreted.
    ##
    ## An empty ("" string) mailbox name argument is a special request to
    ## return the hierarchy delimiter and the root name of the name given
    ## in the reference.  The value returned as the root MAY be the empty
    ## string if the reference is non-rooted or is an empty string.  In
    ## all cases, a hierarchy delimiter (or NIL if there is no hierarchy)
    ## is returned.  This permits a client to get the hierarchy delimiter
    ## (or find out that the mailbox names are flat) even when no
    ## mailboxes by that name currently exist.
    ##
    ## The reference and mailbox name arguments are interpreted into a
    ## canonical form that represents an unambiguous left-to-right
    ## hierarchy.  The returned mailbox names will be in the interpreted
    ## form.
    ##
    ##     Note: The interpretation of the reference argument is
    ##     implementation-defined.  It depends upon whether the
    ##     server implementation has a concept of the "current
    ##     working directory" and leading "break out characters",
    ##     which override the current working directory.
    ##
    ##     For example, on a server which exports a UNIX or NT
    ##     filesystem, the reference argument contains the current
    ##     working directory, and the mailbox name argument would
    ##     contain the name as interpreted in the current working
    ##     directory.
    ##
    ##     If a server implementation has no concept of break out
    ##     characters, the canonical form is normally the reference
    ##     name appended with the mailbox name.  Note that if the
    ##     server implements the namespace convention (section
    ##     5.1.2), "#" is a break out character and must be treated
    ##     as such.
    ##
    ##     If the reference argument is not a level of mailbox
    ##     hierarchy (that is, it is a \NoInferiors name), and/or
    ##     the reference argument does not end with the hierarchy
    ##     delimiter, it is implementation-dependent how this is
    ##     interpreted.  For example, a reference of "foo/bar" and
    ##     mailbox name of "rag/baz" could be interpreted as
    ##     "foo/bar/rag/baz", "foo/barrag/baz", or "foo/rag/baz".
    ##     A client SHOULD NOT use such a reference argument except
    ##     at the explicit request of the user.  A hierarchical
    ##     browser MUST NOT make any assumptions about server
    ##     interpretation of the reference unless the reference is
    ##     a level of mailbox hierarchy AND ends with the hierarchy
    ##     delimiter.
    ##
    ## Any part of the reference argument that is included in the
    ## interpreted form SHOULD prefix the interpreted form.  It SHOULD
    ## also be in the same form as the reference name argument.  This
    ## rule permits the client to determine if the returned mailbox name
    ## is in the context of the reference argument, or if something about
    ## the mailbox argument overrode the reference argument.  Without
    ## this rule, the client would have to have knowledge of the server's
    ## naming semantics including what characters are "breakouts" that
    ## override a naming context.

    result = await client.send("LIST " & reference & " " & mailbox, listener)


proc lsub*(client: ImapClient | AsyncImapClient, reference: string = "\"\"", mailbox: string = "\"*\"", listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.9. LSUB Command
    ##
    ## The LSUB command returns a subset of names from the set of names
    ## that the user has declared as being "active" or "subscribed".
    ## Zero or more untagged LSUB replies are returned.  The arguments to
    ## LSUB are in the same form as those for LIST.
    ##
    ## The returned untagged LSUB response MAY contain different mailbox
    ## flags from a LIST untagged response.  If this should happen, the
    ## flags in the untagged LIST are considered more authoritative.
    ##
    ## A special situation occurs when using LSUB with the % wildcard.
    ## Consider what happens if "foo/bar" (with a hierarchy delimiter of
    ## "/") is subscribed but "foo" is not.  A "%" wildcard to LSUB must
    ## return foo, not foo/bar, in the LSUB response, and it MUST be
    ## flagged with the \Noselect attribute.
    ##
    ## The server MUST NOT unilaterally remove an existing mailbox name
    ## from the subscription list even if a mailbox by that name no
    ## longer exists.

    result = await client.send("LSUB " & reference & " " & mailbox, listener)


type StatusItem* = enum
    siMessages = "MESSAGES"
    siRecent = "RECENT"
    siUidnext = "UIDNEXT"
    siUidvalidity = "UIDVALIDITY"
    siUnseen = "UNSEEN"


proc status*(client: ImapClient | AsyncImapClient, mailbox: string, items: set[StatusItem] = {siMessages}, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.10. STATUS Command
    ## 
    ## The STATUS command requests the status of the indicated mailbox.
    ## It does not change the currently selected mailbox, nor does it
    ## affect the state of any messages in the queried mailbox (in
    ## particular, STATUS MUST NOT cause messages to lose the \Recent
    ## flag).
    ##
    ## The STATUS command provides an alternative to opening a second
    ## IMAP4rev1 connection and doing an EXAMINE command on a mailbox to
    ## query that mailbox's status without deselecting the current
    ## mailbox in the first IMAP4rev1 connection.
    ##
    ## Unlike the LIST command, the STATUS command is not guaranteed to
    ## be fast in its response.  Under certain circumstances, it can be
    ## quite slow.  In some implementations, the server is obliged to
    ## open the mailbox read-only internally to obtain certain status
    ## information.  Also unlike the LIST command, the STATUS command
    ## does not accept wildcards.
    ##
    ##    Note: The STATUS command is intended to access the
    ##    status of mailboxes other than the currently selected
    ##    mailbox.  Because the STATUS command can cause the
    ##    mailbox to be opened internally, and because this
    ##    information is available by other means on the selected
    ##    mailbox, the STATUS command SHOULD NOT be used on the
    ##    currently selected mailbox.
    ##
    ##    The STATUS command MUST NOT be used as a "check for new
    ##    messages in the selected mailbox" operation (refer to
    ##    sections 7, 7.3.1, and 7.3.2 for more information about
    ##    the proper method for new message checking).
    ##
    ##    Because the STATUS command is not guaranteed to be fast
    ##    in its results, clients SHOULD NOT expect to be able to
    ##    issue many consecutive STATUS commands and obtain
    ##    reasonable performance.

    var cmd = "STATUS " & mailbox & "("
    for item in items:
        cmd &= $item & " "
    cmd[cmd.len - 1] = ')'
    result = await client.send(cmd, listener)


proc append*(client: ImapClient | AsyncImapClient, mailbox, flags, msg: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.3.11. APPEND Command
    ##
    ## The APPEND command appends the literal argument as a new message
    ## to the end of the specified destination mailbox.  This argument
    ## SHOULD be in the format of an [RFC-2822] message.  8-bit
    ## characters are permitted in the message.  A server implementation
    ## that is unable to preserve 8-bit data properly MUST be able to
    ## reversibly convert 8-bit APPEND data to 7-bit using a [MIME-IMB]
    ## content transfer encoding.
    ##
    ##     Note: There MAY be exceptions, e.g., draft messages, in
    ##     which required [RFC-2822] header lines are omitted in
    ##     the message literal argument to APPEND.  The full
    ##     implications of doing so MUST be understood and
    ##     carefully weighed.
    ##
    ## If a flag parenthesized list is specified, the flags SHOULD be set
    ## in the resulting message; otherwise, the flag list of the
    ## resulting message is set to empty by default.  In either case, the
    ## Recent flag is also set.
    ##
    ## If a date-time is specified, the internal date SHOULD be set in
    ## the resulting message; otherwise, the internal date of the
    ## resulting message is set to the current date and time by default.
    ##
    ## If the append is unsuccessful for any reason, the mailbox MUST be
    ## restored to its state before the APPEND attempt; no partial
    ## appending is permitted.
    ##
    ## If the destination mailbox does not exist, a server MUST return an
    ## error, and MUST NOT automatically create the mailbox.  Unless it
    ## is certain that the destination mailbox can not be created, the
    ## server MUST send the response code "[TRYCREATE]" as the prefix of
    ## the text of the tagged NO response.  This gives a hint to the
    ## client that it can attempt a CREATE command and retry the APPEND
    ## if the CREATE is successful.
    ##
    ## If the mailbox is currently selected, the normal new message
    ## actions SHOULD occur.  Specifically, the server SHOULD notify the
    ## client immediately via an untagged EXISTS response.  If the server
    ## does not do so, the client MAY issue a NOOP command (or failing
    ## that, a CHECK command) after one or more APPEND commands.

    var tag = client.genTag()
    await client.socket.send(tag & " " & " APPEND " & (if flags != "" : mailbox & " (" & flags & ")" else: mailbox) & " {" & $msg.len & "}")

    let line = await client.socket.recvLine()

    if line.startsWith("+"):
        await client.socket.send(msg)
        await client.socket.send(CRLF)
        result = await client.getData(tag, listener)
    else:
        result = client.checkLine(tag, line)
    
    
proc check*(client: ImapClient | AsyncImapClient, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.4.1.  CHECK Command
    ##
    ## The CHECK command requests a checkpoint of the currently selected
    ## mailbox.  A checkpoint refers to any implementation-dependent
    ## housekeeping associated with the mailbox (e.g., resolving the
    ## server's in-memory state of the mailbox with the state on its
    ## disk) that is not normally executed as part of each command.  A
    ## checkpoint MAY take a non-instantaneous amount of real time to
    ## complete.  If a server implementation has no such housekeeping
    ## considerations, CHECK is equivalent to NOOP.
    ## 
    ## There is no guarantee that an EXISTS untagged response will happen
    ## as a result of CHECK.  NOOP, not CHECK, SHOULD be used for new
    ## message polling.
    
    result = await client.send("CHECK", listener)


proc close*(client: ImapClient | AsyncImapClient, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.4.2.  CLOSE Command
    ##
    ## The CLOSE command permanently removes all messages that have the
    ## \Deleted flag set from the currently selected mailbox, and returns
    ## to the authenticated state from the selected state.  No untagged
    ## EXPUNGE responses are sent.
    ##
    ## No messages are removed, and no error is given, if the mailbox is
    ## selected by an EXAMINE command or is otherwise selected read-only.
    ##
    ## Even if a mailbox is selected, a SELECT, EXAMINE, or LOGOUT
    ## command MAY be issued without previously issuing a CLOSE command.
    ## The SELECT, EXAMINE, and LOGOUT commands implicitly close the
    ## currently selected mailbox without doing an expunge.  However,
    ## when many messages are deleted, a CLOSE-LOGOUT or CLOSE-SELECT
    ## sequence is considerably faster than an EXPUNGE-LOGOUT or
    ## EXPUNGE-SELECT because no untagged EXPUNGE responses (which the
    ## client would probably ignore) are sent.

    result = await client.send("CLOSE", listener)
    
        
proc expunge*(client: ImapClient | AsyncImapClient, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.4.3.  EXPUNGE Command
    ##
    ## The EXPUNGE command permanently removes all messages that have the
    ## \Deleted flag set from the currently selected mailbox.  Before
    ## returning an OK to the client, an untagged EXPUNGE response is
    ## sent for each message that is removed.
    
    result = await client.send("EXPUNGE", listener)


proc search*(client: ImapClient | AsyncImapClient, query: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.4.4.  SEARCH Command
    ##
    ## The SEARCH command searches the mailbox for messages that match
    ## the given searching criteria.  Searching criteria consist of one
    ## or more search keys.  The untagged SEARCH response from the server
    ## contains a listing of message sequence numbers corresponding to
    ## those messages that match the searching criteria.
    ##
    ## When multiple keys are specified, the result is the intersection
    ## (AND function) of all the messages that match those keys.  For
    ## example, the criteria DELETED FROM "SMITH" SINCE 1-Feb-1994 refers
    ## to all deleted messages from Smith that were placed in the mailbox
    ## since February 1, 1994.  A search key can also be a parenthesized
    ## list of one or more search keys (e.g., for use with the OR and NOT
    ## keys).
    
    result = await client.send("SEARCH " & query, listener)


proc fetch*(client: ImapClient | AsyncImapClient, mid: string, item: string = "FULL", listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.4.5.  FETCH Command
    ##
    ## The FETCH command retrieves data associated with a message in the
    ## mailbox.  The data items to be fetched can be either a single atom
    ## or a parenthesized list.
    ##
    ## Most data items, identified in the formal syntax under the
    ## msg-att-static rule, are static and MUST NOT change for any
    ## particular message.  Other data items, identified in the formal
    ## syntax under the msg-att-dynamic rule, MAY change, either as a
    ## result of a STORE command or due to external events.
    ##
    ##     For example, if a client receives an ENVELOPE for a
    ##     message when it already knows the envelope, it can
    ##     safely ignore the newly transmitted envelope.
    ##
    ## There are three macros which specify commonly-used sets of data
    ## items, and can be used instead of data items.  A macro must be
    ## used by itself, and not in conjunction with other macros or data
    ## items.

    result = await client.send("FETCH " & mid & " " & item, listener)
    
    
proc fetch*(client: ImapClient | AsyncImapClient, startmid, endmid: string, item: string = "FULL", listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    result = await client.send("FETCH " & startmid & ":" & endmid & " " & item, listener)


proc store*(client: ImapClient | AsyncImapClient, mid: string, item, value: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.4.6.  STORE Command
    ##
    ## The STORE command alters data associated with a message in the
    ## mailbox.  Normally, STORE will return the updated value of the
    ## data with an untagged FETCH response.  A suffix of ".SILENT" in
    ## the data item name prevents the untagged FETCH, and the server
    ## SHOULD assume that the client has determined the updated value
    ## itself or does not care about the updated value.
    ##
    ##     Note: Regardless of whether or not the ".SILENT" suffix
    ##     was used, the server SHOULD send an untagged FETCH
    ##     response if a change to a message's flags from an
    ##     external source is observed.  The intent is that the
    ##     status of the flags is determinate without a race
    ##     condition.

    result = await client.send("STORE " & mid & " " & item & " " & value, listener)


proc store*(client: ImapClient | AsyncImapClient, startmid, endmid: string, item, value: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    result = await client.send("STORE " & startmid & ":" & endmid & " " & item & " " & value, listener)


proc copy*(client: ImapClient | AsyncImapClient, mid: string, mailbox: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    ## 6.4.7.  COPY Command
    ##
    ## The COPY command copies the specified message(s) to the end of the
    ## specified destination mailbox.  The flags and internal date of the
    ## message(s) SHOULD be preserved, and the Recent flag SHOULD be set,
    ## in the copy.
    ##
    ## If the destination mailbox does not exist, a server SHOULD return
    ## an error.  It SHOULD NOT automatically create the mailbox.  Unless
    ## it is certain that the destination mailbox can not be created, the
    ## server MUST send the response code "[TRYCREATE]" as the prefix of
    ## the text of the tagged NO response.  This gives a hint to the
    ## client that it can attempt a CREATE command and retry the COPY if
    ## the CREATE is successful.
    ##
    ## If the COPY command is unsuccessful for any reason, server
    ## implementations MUST restore the destination mailbox to its state
    ## before the COPY attempt.
    
    result = await client.send("COPY " & mid & " " & mailbox, listener)
    

proc copy*(client: ImapClient | AsyncImapClient, startmid, endmid: string, mailbox: string, listener: ImapListener = nil): Future[ImapCommandStatus] {.multisync, discardable.} =
    result = await client.send("COPY " & startmid & ":" & endmid & " " & mailbox, listener)