# A Service provider for managing HTTP Sessions
# in a Supranim application.
#
#   (c) 2025 George Lemon / Made by Humans from OpenPeeps
#   https://supranim.com | https://github.com/supranim
#   
#   Released under the MIT License.

import pkg/supranim/core/[services, paths]
import pkg/nimcypher

initService HttpSession[Singleton]:
  backend do:
    import std/[times, json, tables, hashes, strutils]
    import pkg/threading/rwlock
    import pkg/supranim/support/[cookie, nanoid]
    from std/cookies import SameSite
    from pkg/supranim/core/application import appInstance, config,
      getStr, getBool, getInt, isNil
    export cookie

    type
      # Configuration Objects
      ConfigHttpAuthenticationResetPassword* = object
        enable: bool = true
          ## Whether to let user reset their password
        require_same_device: bool
          ## Require the user to be on the same device
          ## that they used to request the reset password link
        require_same_ip: bool
          ## Require the user to be on the same IP
          ## that they used to create the account.

      ConfigHttpAuthentication* = object
        enableMultipleSessions*: bool = true
          ## Whether to allow multiple device sessions for the same user.
          ## If this is set to `false`, a new session cannot be created
          ## if there is an existing active session for the same user. This can be
          ## used to prevent account sharing, but it can also be inconvenient
          ## for users who use multiple devices. If this is set to `true`,
          ## a new session will be created for each login, and all sessions
          ## will be valid until they expire or the user logs out
        enableRememberMe*: bool = true
          # Allow the user to check the `remember me` checkbox to keep them logged in.
        case enable_2fa: bool
          # Enable two factor authentication.
          of false: discard
          of true:
            discard # todo
        reset_password: ConfigHttpAuthenticationResetPassword
          ## Configuration for the reset password
          ## process. This is used to send a reset password
          ## email to the user.
      
      ConfigHttpRegistration* = object
        enable: bool = true
          # Whether to enable user registration
        error_message_prevent_enumeration: bool
          # Prevents user enumeration by returning the same
          # messages for most failed/success registration attempts.
      
      ConfigHttpSessionCookie* = object
        ## Configuration for the session cookie. This is used to set the cookie
        name: string = "ssid"
          # The name of the session cookie.
        domain: string = ""
          # The domain of the session cookie. Empty means a host-only
          # cookie (recommended for `localhost` / `127.0.0.1` development).
        path: string = "/"
          # The path of the session cookie.
        httpOnly: bool = true
          # Whether the cookie is inaccessible to client-side scripts.
        sameSite: SameSite = SameSite.Strict
          # The `SameSite` policy. Note `None` requires `Secure` to be
          # emitted, otherwise browsers reject the cookie.
        secure: CookieSecureMode = secureAuto
          # When to emit the `Secure` attribute. `secureAuto` (default)
          # emits it only when the effective request scheme is `https`,
          # so plain `http://localhost` keeps working on Safari (which,
          # unlike Chrome/Firefox, does not treat `localhost` as a secure
          # context and drops `Secure` cookies over plain HTTP).
        trustProxy: bool = true
          # Honor `X-Forwarded-Proto` / `Forwarded` headers when deciding
          # the effective scheme. Enable when running behind a reverse
          # proxy that sets them (e.g. nginx with
          # `proxy_set_header X-Forwarded-Proto $scheme;`).
        expiration: Option[DateTime] 
          # The expiration time of the session cookie.
          # if this is set to `none(DateTime)` the `ssid`
          # cookie will be a session-based cookie and it
          # will be deleted when the browser is closed.

      ConfigHttpSession* = object
        ## Configuration for the session management, including cookie settings
        expiration*: Duration
          ## The duration after which the session will expire.
          ## This is used to determine when to delete expired sessions.
        session_cookie*: ConfigHttpSessionCookie
          ## Configuration for the session cookie.
        authentication*: ConfigHttpAuthentication
          ## Configuration for the authentication process.
        registration*: ConfigHttpRegistration
          ## Configuration for the registration process.

      # Session
      Notification* = string
      CSRFFormIdentifier* = string
        # A unique identifier for the CSRF token.
        # This is used to identify the form that the
        # CSRF token is associated with. Usually
        # this is the form action URL.

      UserSessionType* = enum
        sessionTypeDefault
          ## A temporary session that will be deleted after a certain time
        sessionTypeRememberMe
          ## A session that will be preserved until the user logs out or the session
          ## is deleted by the server.

      UserSessionObj* = ref object
        `type`: UserSessionType
        id: string
          # A unique NanoID that that represents the user session
          # the id can be regenerated by the server when the user
          # session renews (in case the session type is set as `sessionTypeRememberMe`)
        userId: Option[string]
          # The user id associated with the session. This is used to
          # identify the user associated with the session without having
          # to query the database for the session payload.
        backend: Table[string, Cookie]
          # A table for holding backend cookies.
        client: Table[string, Cookie]
          # A public table for holding client cookies that will be
          # sent within the response.
        notifications: Table[string, seq[Notification]]
          # A table that holds flash bag notification messages.
          # This is useful for displaying notification messages
          # after a redirect, or a submitted form
        created, lastAccess: DateTime
          # The created and last access time of the session.
          # This is used to determine when to expire the session.
        hasExpired: bool
          # Marks `UserSessionObj` as expired before deleting it.
          # Expired sessions are cleared by the SessionCleaner
          # in a separate process
        payload: JsonNode
          # A JSON object that can be used to store
          # any payload related to the current user session.
        rememberToken: Option[string]
          # generated when user checks the `remember me`
          # checkbox to keep it logged in until they log out
          # or the session is deleted by the server
        csrfSecretKey: string
          # A secret key used to generate CSRF tokens. This key
          # is unique for each session and is used to create
          # HMAC-based CSRF tokens.
        csrfTokens: Table[CSRFFormIdentifier, string]
          # a table that holds the generated CSRF tokens for
          # each form identifier. this is used to validate the CSRF
          # token when the form is submitted.

      Sessions = Table[string, UserSessionObj]

      SessionStorageType = enum
        sessionDBStorage
        sessionFileStorage

      HttpSession = object
        rwlock: RwLock
        keypair: string
        nonce: string
          # A unique nonce used for encrypting and decrypting session
          # data when using file storage. This should be generated once and stored securely.
        storageType: SessionStorageType
          # The storage type for the sessions. This can be either `sessionDBStorage` or `sessionFileStorage`.
        sessions: Sessions
          # A table that holds all the active user sessions. The key is the session id.
        staleMappings: Table[string, string]
          # Maps stale cookie IDs to new session IDs, to prevent duplicate
          # sessions from being created when the browser sends concurrent
          # requests with the same stale cookie.
        config*: ConfigHttpSession
          # Configuration for the session management, including cookie settings
          # and authentication options.

      HttpSessionError* = object of CatchableError

    proc parseSessionSameSite(s: string): SameSite =
      ## Maps a `same_site` config value to `SameSite`, defaulting to `Strict`.
      case s.strip().toLowerAscii()
      of "lax": SameSite.Lax
      of "none": SameSite.None
      else: SameSite.Strict

    proc loadSessionConfig*(): ConfigHttpSession =
      ## Builds the session configuration from `config/session.*`
      ## (`App.config("session.*")`), falling back to code defaults for
      ## every missing file or key. Never raises: when the application
      ## is not initialized yet (e.g. in tests) the defaults apply.
      result = ConfigHttpSession(
        expiration: initDuration(hours = 720),
        session_cookie: ConfigHttpSessionCookie(),
        authentication: ConfigHttpAuthentication(
          enableMultipleSessions: true,
          enableRememberMe: true,
          enable_2fa: false,
          reset_password: ConfigHttpAuthenticationResetPassword()
        ),
        registration: ConfigHttpRegistration(
          enable: true,
          error_message_prevent_enumeration: true
        )
      )
      try:
        let app = appInstance()
        if system.isNil(app) or system.isNil(app.configs):
          return
        template overrideStr(key: string, dst: untyped) =
          block:
            let v = app.config(key)
            if not v.isNil and v.getStr.len > 0:
              dst = v.getStr
        template overrideBool(key: string, dst: untyped) =
          block:
            let v = app.config(key)
            if not v.isNil:
              dst = v.getBool
        var expirationHours = 720'i64
        block:
          let v = app.config("session.expiration_hours")
          if not v.isNil:
            expirationHours = v.getInt
        result.expiration = initDuration(hours = expirationHours)
        overrideStr("session.cookie.name", result.session_cookie.name)
        overrideStr("session.cookie.domain", result.session_cookie.domain)
        overrideStr("session.cookie.path", result.session_cookie.path)
        overrideBool("session.cookie.http_only", result.session_cookie.httpOnly)
        overrideBool("session.cookie.trust_proxy", result.session_cookie.trustProxy)
        block:
          let v = app.config("session.cookie.same_site")
          if not v.isNil and v.getStr.len > 0:
            result.session_cookie.sameSite = parseSessionSameSite(v.getStr)
        block:
          let v = app.config("session.cookie.secure")
          if not v.isNil and v.getStr.len > 0:
            result.session_cookie.secure = parseSecureMode(v.getStr)
        overrideBool("session.authentication.enable_multiple_sessions",
          result.authentication.enableMultipleSessions)
        overrideBool("session.authentication.enable_remember_me",
          result.authentication.enableRememberMe)
        overrideBool("session.authentication.enable_2fa",
          result.authentication.enable_2fa)
        overrideBool("session.authentication.reset_password.enable",
          result.authentication.reset_password.enable)
        overrideBool("session.authentication.reset_password.require_same_device",
          result.authentication.reset_password.require_same_device)
        overrideBool("session.authentication.reset_password.require_same_ip",
          result.authentication.reset_password.require_same_ip)
        overrideBool("session.registration.enable",
          result.registration.enable)
        overrideBool("session.registration.error_message_prevent_enumeration",
          result.registration.error_message_prevent_enumeration)
      except CatchableError:
        discard

    # forward declaration
    proc session*(): ptr HttpSession {.inline.}
    proc initSavedSessions*(instance: ptr HttpSession)

    proc sessionCookieName*(): string =
      ## Returns the configured session cookie name (`ssid` by default).
      let n = session()[].config.session_cookie.name
      if n.len > 0: n else: "ssid"

    proc newUserSession*(userData: JsonNode, reqPath: string, staleSsid: Option[string] = none(string)): UserSessionObj =
      ## Creates a new session object
      assert userData.kind == JObject
      var id: string
      let instance = session()
      writeWith(instance[].rwlock):
        # Check if another request already created a session for this stale cookie
        if staleSsid.isSome:
          let staleId = staleSsid.get()
          if instance[].staleMappings.hasKey(staleId):
            let resolvedId = instance[].staleMappings[staleId]
            if instance.sessions.hasKey(resolvedId):
              return instance.sessions[resolvedId]
        while true:
          id = nanoid.generate(size = 42)
          if not instance.sessions.hasKey(id): break
        let createdAt = now()
        result = UserSessionObj(
          id: id,
          created: createdAt,
          lastAccess: createdAt,
          csrfSecretKey: nanoid.generate(size = 32),
          payload: userData,
          notifications: initTable[string, seq[Notification]](),
          csrfTokens: initTable[CSRFFormIdentifier, string](),
          client: initTable[string, Cookie](),
          backend: initTable[string, Cookie]()
        )
        result.client[sessionCookieName()] = newCookie(sessionCookieName(), id)
        instance.sessions[id] = result
        if staleSsid.isSome:
          instance[].staleMappings[staleSsid.get()] = id

    proc addUserSessionWith(instance: ptr HttpSession,
          id: string, createdAt: DateTime, userData: JsonNode) =
      ## Creates a new session object with a custom id and createdAt time
      assert userData.kind == JObject
      let userSession = UserSessionObj(
        id: id,
        created: createdAt,
        lastAccess: createdAt,
        csrfSecretKey: nanoid.generate(size = 32),
        payload: userData,
        notifications: initTable[string, seq[Notification]](),
        csrfTokens: initTable[CSRFFormIdentifier, string](),
        client: initTable[string, Cookie](),
        backend: initTable[string, Cookie]()
      )
      userSession.client[sessionCookieName()] = newCookie(sessionCookieName(), id)
      instance[].sessions[id] = userSession

  client do:
    import std/times
    import pkg/openparser/json
    
    when defined supraDBMainSqlite:
      import pkg/ozark/driver/sqlite
    else:
      import pkg/ozark/driver/psql

    from pkg/supranim/core/request import Request, getClientData, getUriPath,
      hasCookies, getCookies, newCookieForRequest
    from pkg/supranim/core/response import Response, addHeader
    from pkg/supranim/support/cookie import parseCookies

    import ../model/user

    proc getSessionIdFromRequest*(req: var Request): Option[string] =
      ## Returns the session id from the request's session cookie,
      ## honoring the configured cookie name.
      if req.hasCookies:
        let jar = parseCookies(req.getCookies().get())
        if not jar.isNil:
          let n = sessionCookieName()
          if jar.hasKey(n):
            return some(jar[n].getValue())

    proc buildSessionCookie*(req: var Request, id: string,
        expirationDate: Option[DateTime] = none(DateTime)): Cookie =
      ## Builds the session cookie honoring `config/session.*` and the
      ## request's effective scheme: `Secure` is emitted per the
      ## configured `secure` mode (`auto` by default), so Safari keeps
      ## working over plain `http://localhost` while proxied HTTPS
      ## traffic still gets `Secure`.
      let c = session()[].config.session_cookie
      req.newCookieForRequest(sessionCookieName(), id,
        mode = c.secure, trustProxy = c.trustProxy,
        expirationDate = expirationDate,
        domain = c.domain, path = c.path,
        httpOnly = c.httpOnly, sameSite = c.sameSite)

    proc session*(): ptr HttpSession {.inline.} =
      ## Returns the Singleton instance of HttpSession
      getHttpSessionInstance(
        proc(instance: ptr HttpSession) =
          {.gcsafe.}:
            initSavedSessions(instance)
            instance[].config = loadSessionConfig()
      ) # `getHttpSessionInstance` auto generated by the service manager
  
    proc getUserSession*(req: var Request): UserSessionObj =
      ## Returns the current user session.
      let ssid = req.getSessionIdFromRequest()
      if ssid.isSome:
        let instance = session()
        readWith(instance[].rwlock):
          if instance.sessions.hasKey(ssid.get()):
            result = instance.sessions[ssid.get()]

    proc getId*(userSession: UserSessionObj): lent string =
      ## Returns the session id
      result = userSession.id

    proc getUserId*(userSession: UserSessionObj): Option[string] =
      ## Returns the user id associated with the session
      result = userSession.userId

    proc initSessionWithHeaders*(req: var Request, res: var Response): UserSessionObj = 
      ## Initializes a new `UserSession` then adds a
      ## `set-cookie` header to the next `res` Response. The cookie
      ## attributes (including `Secure`) follow `config/session.*` and
      ## the request's effective scheme.
      let
        staleSsid = req.getSessionIdFromRequest()
        cookieName = sessionCookieName()
      # Clear stale cookie from browser, mirroring the session cookie
      # attributes so the browser actually drops it.
      if staleSsid.isSome:
        var clearCookie = buildSessionCookie(req, "")
        clearCookie.expires()
        res.addHeader("set-cookie", $clearCookie)
      result = newUserSession(req.getClientData(), req.getUriPath(), staleSsid)
      if likely(result.client.hasKey(cookieName)):
        result.client[cookieName] = buildSessionCookie(req, result.id)
        res.addHeader("set-cookie", $result.client[cookieName])
      else:
        raise newException(HttpSessionError, "Could not create a new Session")

    proc destroy*(userSession: UserSessionObj, res: var Response) =
      ## Deletes the session object and overwrites the
      ## `set-cookie` header with an expired cookie.
      ## 
      ## This will delete the session cookie from backend and client.
      ## The stored cookie attributes (including `Secure`) are preserved
      ## so the browser matches and drops the exact cookie it holds.
      let
        instance = session()
        name = sessionCookieName()
      assert userSession.client.hasKey(name)
      var userCookie = userSession.client[name]
      userCookie.expires()
      userSession.client[name] = userCookie
      res.addHeader("set-cookie", $userCookie)
      writeWith(instance[].rwlock):
        instance.sessions.del(userSession.id)
    
    proc checkPayload(userPayload, reqPayload: JsonNode): bool =
      # Checks if the session payload matches the request payload.
      for k, v in userPayload:
        if likely(reqPayload.hasKey(k)):
          if likely(v.getStr() == reqPayload[k].getStr()):
            result = true
            continue # truthy. continue to check user data
          return false
        return false

    proc checkAuthenticity*(userSession: UserSessionObj, reqPayload: JsonNode): bool =
      ## Checks if the session payload matches the request payload. This is a basic check
      ## to prevent session hijacking by comparing the session payload with the client data
      ## of the request. The session will be considered authentic if all the key-value
      ## pairs in the session payload match the corresponding key-value pairs in the request payload.
      userSession.payload.checkPayload(reqPayload)

    template withSession*(code) {.dirty.} =
      ## Template for executing a block of code
      ## that requires a user session.
      block:
        var userSession: UserSessionObj = req.getUserSession()
        if userSession == nil: # init a new session
          userSession = initSessionWithHeaders(req, res)
        else:
          if userSession.isAuthenticated() and not userSession.checkAuthenticity(req.getClientData()):
            # the session is not authentic and may have been hijacked.
            # will destroy the session and create a new one
            # which basically, will log the user out and require
            # them to log in again
            userSession.destroy(res)
            userSession = initSessionWithHeaders(req, res)
        code

    template withUserSession*(code) {.dirty.} =
      ## Template for executing a block of code that requires a user session.
      ## This template can be used inside of a `controller`/`middleware` context
      block:
        let userSession: UserSessionObj = req.getUserSession()
        if userSession != nil:
          code # execute code block

    template withDBUserSession*(code) {.dirty.} =
      ## Template for executing a block of code that requires a user session and a database connection.
      ## This template can be used inside of a `controller`/`middleware` context
      withSession do:
        withDBPool do:
          let storedSession =
                Models.table(UserSessions)
                      .select(["user_id", "created_at", "last_access"])
                      .where("session_id", userSession.getId())
                      .getAll().first()
          if storedSession != nil:
            let userId = storedSession.getUserId()
            let user =
                  Models.table(Users)
                        .select(["id"])
                        .where("id", userId)
                        .getAll().first()
            if user != nil:
              code # execute code block with database connection and user session

    proc isAuthenticated*(userSession: UserSessionObj): bool =
      ## Determine if the user is authenticated by performing a database
      ## query to check if the session is valid.
      withDBPool do:
        result = userSession.payload != nil
        if result:
          let anySessions = Models.table(UserSessions)
                                  .selectAll()
                                  .where("session_id", userSession.id)
                                  .getAll()
          result = anySessions.isEmpty() == false
          if result:
            let storedSession = anySessions.first()
            let storedPayload = fromJson(storedSession.getPayload())
            # set the user id in the session object for later use
            userSession.userId = some(storedSession.getUserId())
            # todo check if the session has expired based on the created_at time in the database
            return userSession.payload.checkPayload(storedPayload)
    
    proc isAuthenticated*(req: var Request, res: var Response): bool =
      ## Determine if the user is authenticated by performing a database
      ## query to check if the session is valid.
      withSession do:
        result = userSession.isAuthenticated()

    proc getAuthUserId*(userSession: UserSessionObj): Option[string] =
      ## Returns the user id based on the current session
      withDBPool do:
        if userSession.payload != nil:
          let anySessions = Models.table(UserSessions)
                                  .select("user_id")
                                  .where("session_id", userSession.id)
                                  .getAll()
          if not anySessions.isEmpty():
            return some(anySessions.first().getUserId())
      none(string)

    proc getCreatedAt*(userSession: UserSessionObj): DateTime =
      ## Returns the session created at time
      userSession.created

    proc getLastAccess*(userSession: UserSessionObj): DateTime =
      ## Returns the session last access time
      userSession.lastAccess

    proc getType*(userSession: UserSessionObj): UserSessionType =
      ## Returns the session type (default or remember-me)
      userSession.`type`

    proc isExpired*(userSession: UserSessionObj): bool =
      ## Returns true if the session has exceeded its configured expiration duration
      let instance = session()
      result = now() - userSession.created > instance[].config.expiration

    proc renewSession*(userSession: UserSessionObj, req: var Request, res: var Response) =
      ## Regenerates the session ID for a remember-me session.
      ## This should be called after successful authentication to prevent session fixation.
      ## The replacement cookie follows `config/session.*` and the request's
      ## effective scheme (Safari-safe `Secure` handling).
      if userSession.`type` != sessionTypeRememberMe:
        return
      let instance = session()
      let name = sessionCookieName()
      var newId: string
      writeWith(instance[].rwlock):
        while true:
          newId = nanoid.generate(size = 42)
          if not instance[].sessions.hasKey(newId): break
      let renewed = buildSessionCookie(req, newId,
        expirationDate = some(userSession.created + instance[].config.expiration))
      writeWith(instance[].rwlock):
        let oldId = userSession.id
        userSession.id = newId
        userSession.client[name] = renewed
        instance[].sessions.del(oldId)
        instance[].sessions[newId] = userSession
      res.addHeader("set-cookie", $userSession.client[name])

    proc initSavedSessions*(instance: ptr HttpSession) =
      ## Initializes the HttpSession service with saved sessions
      ## from the database.
      var tempRw = createRwLock()
      copyMem(addr(instance[].rwlock), addr(tempRw), sizeof(RwLock))
      zeroMem(addr(tempRw), sizeof(RwLock))
      if instance[].storageType == sessionDBStorage:
        withDBPool do:
          let anySessions = Models.table(UserSessions).selectAll().getAll()
          for s in anySessions:
            try:
              let payload = fromJson(s.getPayload())
              let id = s.getSessionId()
              let createdAt = parse(s.getCreatedAt(), "yyyy-MM-dd HH:mm:sszz")
              # if the session has expired, skip it and let the SessionCleaner process handle it
              if now() - createdAt > initDuration(days = 30): continue
              addUserSessionWith(instance, id, createdAt, %*{
                  "ip": payload["ip"],
                  "platform": payload["platform"],
                  "agent": payload["agent"],
                  "sec-ch-ua": payload["sec-ch-ua"]
                })
            except JsonParsingError as e:
              echo e.msg # todo log the error somewhere and
              continue
            except TimeParseError as e:
              echo e.msg # todo log the error somewhere and
              continue

    #
    # Manage UserSession's payload
    #
    proc updatePayload*(userSession: UserSessionObj, payload: JsonNode) =
      ## Updates the session payload
      userSession.payload = payload

    proc getPayload*(userSession: UserSessionObj): JsonNode =
      ## Retrieve the session payload
      result = userSession.payload

    template saveSession*(userId: string, userSession: UserSessionObj) =
      ## Saves the current session to the database.
      Models.table(UserSessions).insert({
        "user_id": userId,
        "session_id": userSession.getId(),
        "payload": toJson(userSession.getPayload()),
        "last_access": $(userSession.getCreatedAt()),
        "created_at": $(userSession.getCreatedAt())
      }).exec()

    proc saveSessionWithPool*(userId: string, userSession: UserSessionObj) =
      ## Saves the current session to the database using a connection pool.
      withDBPool do:
        saveSession(userid, userSession)

    #
    # CSRF handlers
    #
    proc genCSRF*(userSession: UserSessionObj, id: string): string =
      ## Generates a new CSRF token for the given form identifier and stores it in the session's `csrfTokens` table.
      ## The CSRF token is generated using HMAC-SHA256 with a unique secret key for each session.
      ## 
      ## The generated token is stored in the `csrfTokens` table with the form identifier as the key.
      ## This allows for validating the token when the form is submitted.
      let instance = session()
      writeWith(instance[].rwlock):
        if userSession.csrfTokens.hasKey(id):
          result = userSession.csrfTokens[id]
        else:
          result = toLowerAscii(sha512HmacHex(userSession.csrfSecretKey, nanoid.generate(size = 8)))
          userSession.csrfTokens[id] = result

    proc validateCSRF*(userSession: UserSessionObj, id, clientToken: string): bool =
      ## Validates the CSRF token submitted by the client against the token stored in the session
      ## for the given form identifier.
      let instance = session()
      writeWith(instance[].rwlock):
        if userSession.csrfTokens.hasKey(id) and userSession.csrfTokens[id] == clientToken:
          userSession.csrfTokens.del(id)
          result = true

    #
    # Flash bag notifications
    #
    template notify*(userSession: UserSessionObj, msg: string, somePath: Option[string] = none(string)) =
      ## Adds a flash message to the session. This message will be
      ## displayed in the next response. This is useful for displaying
      ## notification messages after a redirect.
      if userSession != nil:
        let path = if somePath.isSome: somePath.get() else: req.getUriPath()
        let instance = session()
        writeWith(instance[].rwlock):
          if not userSession.notifications.hasKey(path):
            userSession.notifications[path] = newSeq[Notification]()
          userSession.notifications[path].add(msg)

    proc getSomeNotifications*(userSession: UserSessionObj, path: string): Option[seq[string]] =
      ## Returns available flash bag notifications.
      if userSession != nil:
        let instance = session()
        writeWith(instance[].rwlock):
          if userSession.notifications.hasKey(path):
            result = some(userSession.notifications[path])
            userSession.notifications.del(path)

    proc getNotifications*(userSession: UserSessionObj, path: string): seq[string] =
      ## Returns available flash bag notifications.
      if userSession != nil:
        let instance = session()
        writeWith(instance[].rwlock):
          if userSession.notifications.hasKey(path):
            result = userSession.notifications[path]
            userSession.notifications.del(path)