# A Service provider for managing HTTP Sessions
# in a Supranim application.
#
#   (c) 2025 George Lemon / Made by Humans from OpenPeeps
#   https://supranim.com | https://github.com/supranim
#   
#   Released under the MIT License.

template getLogin*(redirectHandlerAlreadyLoggedin: untyped, layout="base") =
  ## renders authentication page
  withSession do:
    if userSession.isAuthenticated():
      # if the user is already authenticated
      # redirect to the account page
      go redirectHandlerAlreadyLoggedin
    else:
      render("auth/login", layout, local = &*{
        "notifications": userSession.getNotifications(req.getUriPath).get(@[]),
        "csrf": userSession.genCSRF("/auth/login")
      })

const
  authErrorMessage* = "Invalid email address or password"

template postLogin*(redirectHandlerSuccess: untyped) = 
  ## handle authentication requests
  withSession do:
    if userSession.isAuthenticated():
      # if the user is already authenticated
      # redirect to the account page
      go redirectHandlerSuccess # redirects to `/account`

    bag req.getFields:
      # validates the request fields
      # if the email address is not valid, notify the user
      # using a specific error message, otherwise use the
      # default error message and redirect to `/auth/login`
      email: tEmail""
      password: tPassword""
      csrf -> callback do(input: string) -> bool:
        # validate the CSRF token required for authentication
        return userSession.validateCSRF("/auth/login", input)
    do:
      # validation failed, let's notify the user
      # and redirect to `/auth/login`
      userSession.notify(authErrorMessage)
      go getAuthLogin # redirects to `/auth/login`
    withDB do:
      let collection =
        Models.table("users").select
              .where("email", req.getFields[0][1]).get()
      if unlikely(collection.isEmpty):
        userSession.notify(authErrorMessage)
        go getAuthLogin # redirects to `/auth/login`

      let user = collection.first()
      if auth.checkPassword(req.getFields[1][1], user.get("password").value):
        if likely(user.get("is_confirmed").value == "t"):
          # Checks if the user account is confirmed before
          # authenticating the user. set payload with user data
          userSession.updatePayload(req.getClientData())

          # store the authenticated user session in the database
          # userSession.saveSession()
          Models.table("user_sessions").insert({
            "user_id": user.get("id").value,
            "session_id": userSession.getId(),
            "payload": toJson(userSession.getPayload()),
            "last_access": $(userSession.getCreatedAt()),
            "created_at": $(userSession.getCreatedAt())
          }).exec()
        else:
          # if the user is not confirmed, notify the user
          # and redirect to `/auth/login`
          userSession.notify("Your account is not confirmed. Check your email inbox or spam folder.")
          go redirectHandlerSuccess # redirects to `/account`
    
    # authentication failed, we'll use the same
    # error message to prevent email enumeration attacks
    userSession.notify(authErrorMessage)
  go redirectHandlerSuccess # redirects to `/account`

template getLogout*(redirectHandlerSuccess: untyped) =
  ## GET handle to destroy user sessions
  withSession do:
    if userSession.isAuthenticated():
      # we neeed an authenticated user session
      # to perform the logout
      withDB do:
        # delete the user session from the database
        assert Models.table("user_sessions").remove
                         .where("session_id", userSession.getId())
                         .execGet() == 1
      # update client cookie with the new expiration
      # date so browser can invalidate the session
      userSession.destroy(res)

  go redirectHandlerSuccess
