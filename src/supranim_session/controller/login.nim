# A Service provider for managing HTTP Sessions
# in a Supranim application.
#
#   (c) 2025 George Lemon / Made by Humans from OpenPeeps
#   https://supranim.com | https://github.com/supranim
#   
#   Released under the MIT License.

import pkg/e2ee
from pkg/ozark/driver/psql import fromDBValue

template getLogin*(redirectHandlerAlreadyLoggedin: untyped, layout="base") =
  ## renders authentication page
  withSession do:
    if userSession.isAuthenticated():
      # if the user is already authenticated
      # redirect to the account page
      go redirectHandlerAlreadyLoggedin
    else:
      render("auth/login", layout, local = &*{
        "notifications": userSession.getNotifications(req.getUriPath),
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
      go redirectHandlerSuccess # redirects to selected controller action

    withBag req.getFields:
      # validates the request fields
      # if the email address is not valid, notify the user
      # using a specific error message, otherwise use the
      # default error message and redirect to `/auth/login`
      email: tEmail""
      password: tPassword""
      csrf -> callback do(input: string) -> bool:
        # validate the CSRF token required for authentication
        result = userSession.validateCSRF("/auth/login", input)
    do:
      # validation failed, let's notify the user
      # and redirect to `/auth/login`
      userSession.notify(authErrorMessage)
      go getAuthLogin # redirects to `/auth/login`
    withDBPool do:
      let fields = req.getFieldsTable().get()
      let collection =
        Models.table(Users).selectAll()
              .where("email", fields["email"]).getAll()

      if unlikely(collection.isEmpty):
        userSession.notify(authErrorMessage)
        go getAuthLogin # redirects to `/auth/login`

      let user {.inject.} = collection.first()
      if e2ee.verifyPassword(fields["password"], user.getPassword()):
        if likely(fromDBValue[bool](user.getIsConfirmed())):
          # Checks if the user account is confirmed before
          # authenticating the user. set payload with user data
          if session().config.authentication.enableMultipleSessions == false:
            # check if only one session is allowed per user, if so,
            # it will prevent the user from logging if they have an active session
            let activeSession = Models.table(UserSessions)
                                      .selectAll()
                                      .where("user_id", user.getId())
                                      .getAll()
            if not activeSession.isEmpty:
              userSession.notify("You have an active session. Please log out from other devices or wait until the session expires.")
              go getAuthLogin # redirects to `/auth/login`

          userSession.updatePayload(req.getClientData())
          # store the authenticated user session in the database
          saveSession(user.getId(), userSession)
          # regenerate session ID to prevent session fixation attacks
          userSession.renewSession(res)
          go redirectHandlerSuccess # redirects to selected controller action
        else:
          # if the user is not confirmed, notify the user
          # and redirect to `/auth/login`
          userSession.notify("Your account is not confirmed. Check your email inbox or spam folder.")
          go getAuthLogin
    
    # authentication failed, we'll use the same
    # error message to prevent email enumeration attacks
    userSession.notify(authErrorMessage)
  go getAuthLogin

template getLogout*(redirectHandlerSuccess: untyped) =
  ## GET handle to destroy user sessions
  withSession do:
    if userSession.isAuthenticated():
      # we neeed an authenticated user session
      # to perform the logout
      withDBPool do:
        # delete the user session from the database
        Models.table(UserSessions).removeRow()
              .where("session_id", userSession.getId())
              .exec()
      # update client cookie with the new expiration
      # date so browser can invalidate the session
      userSession.destroy(res)
  go redirectHandlerSuccess
