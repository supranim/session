# A Service provider for managing HTTP Sessions
# in a Supranim application.
#
#   (c) 2025 George Lemon / Made by Humans from OpenPeeps
#   https://supranim.com | https://github.com/supranim
#   
#   Released under the MIT License.

const forgotPasswordSubmitMessage* =
  "A reset password link has been sent to your email address. Check your inbox or spam folder."

template getForgotPassword*(redirectHandlerSuccess: untyped, layout="base") =
  if unlikely(isAuth()):
    # already loggedin, redirect to `getAccount`
    go redirectHandlerSuccess
  withSession do:
    render("auth.forgot", layout, local = &*{
      "notifications": userSession.getNotifications(req.getUriPath).get(@[]),
      "csrf": userSession.genCSRF("/auth/forgot-password")
    })

template postForgotPassword*(redirectHandlerSuccess: untyped) =
  ## Handle forgot password requests.
  withUserSession do:
    if unlikely(isAuth()):
      # already loggedin, redirect to `/account`
      go redirectHandlerSuccess

    bag req.getFields:
      # default error message for invalid emails
      email: tEmail"Email address is not valid"
      csrf -> callback do(input: string) -> bool:
        # validate the CSRF token required for resetting the password
        return userSession.validateCSRF("/auth/forgot-password", input)
    do:
      # if the email address is not valid, notify the user
      # and redirect to `/auth/forgot-password`
      let invalidEmailMsg = inputBag.getErrors.toSeq()[0][1]
      userSession.notify(invalidEmailMsg)
      go getAuthForgotPassword # redirects to `/auth/forgot-password`

    # emit `account.request.reset` event to handle the
    # password reset request. this event is spawned in a new thread
    # to avoid blocking the request.
    event().emit("account.password.request", some(@[req.getFields[0][1]]))

    # notify the user that a reset password link has been
    # sent to the given email address. Same message is used
    # even if the email address is not registered in the database
    # (to prevent email enumeration attacks).
    userSession.notify(forgotPasswordSubmitMessage)

  # redirects to `/auth/forgot-password`
  go getAuthForgotPassword

template getResetPassword*(redirectHandlerSuccess: untyped, layout = "base") =
  ## Handle GET requests for resetting the password.
  if unlikely(isAuth()):
    # already loggedin, redirect to `getAccount`
    go redirectHandlerSuccess
  withSession do:
    let query = req.getQueryTable()
    if query.hasKey("token"):
      let reqToken {.inject.} = query["token"]
      withDBPool do:
        let passRequestRes =
              Models.table(UserAccountPasswordResets)
                    .selectAll()
                    .where("token", reqToken)
                    .getAll()
        if unlikely(passRequestRes.isEmpty):
          # if requested token is not found in the database
          # notify the user and redirect to `/auth/forgot-password`
          userSession.notify("Invalid reset password link", some("/auth/forgot-password"))
          go getAuthForgotPassword
        else:
          let
            expValue = passRequestRes.first().getExpiresAt()
            expiresAt: DateTime = times.parse(expValue, "yyyy-MM-dd HH:mm:sszz")
          # check if the token is expired if the token is
          # expired, notify the user and redirect to `/auth/forgot-password`
          if now() >= expiresAt:
            userSession.notify("The link has expired. Please, request a new one.", some("/auth/forgot-password"))
            go getAuthForgotPassword # redirects to `/auth/forgot-password`

      render("auth.reset", layout, local = &*{
        "resetToken": reqToken,
        "notifications": userSession.getNotifications(req.getUriPath).get(@[]),
        "csrf": userSession.genCSRF("/auth/reset-password")
      })
    else:
      # if the token is not present in the query string,
      # redirect to `/auth/login`
      userSession.notify("Invalid reset password link", some("/auth/forgot-password"))
      go getAuthForgotPassword # redirects to `/auth/forgot-password`

template postResetPassword* =
  ## Handle POST requests for resetting the password.
  withSession do:
    let q {.inject.} = req.getFieldsTable().get()
    withValidator req.getFields:
      new_password: tPasswordStrength""
        # a strong password is required
      new_password_confirm -> callback do(input: string) -> bool:
        # ensure the password matches the confirmation password
        q["new_password_confirm"] == q.getOrDefault"new_password"
      token -> callback do(input: string) -> bool:
        # validate the token required for resetting the password
        return true
      csrf -> callback do(input: string) -> bool:
        # validate the CSRF token required for resetting the password
        return userSession.validateCSRF("/auth/reset-password", input)
    do:
      var hasValidToken: bool
      let fields = inputBag.getErrors.toSeq().mapIt(it[0])
      hasValidToken = fields.contains("token") == false
      if hasValidToken:
        # set the flash message to notify the user
        # that the password is not strong enough
        # and redirect to `/auth/reset-password`
        userSession.notify("The entered password is not strong enough")
        go getAuthResetPassword, @[("token", q["token"])]
      else:
        go getAuthForgotPassword # redirects to `/auth/forgot-password`
    
    withDBPool do:
      let tokenRes = Models.table(UserAccountPasswordResets)
                          .selectAll()
                          .where("token", q["token"]).getAll()
      if not tokenRes.isEmpty:
        let
          token {.inject.} = tokenRes.first()
          expValue = token.getExpiresAt()
          expiresAt: DateTime = times.parse(expValue, "yyyy-MM-dd HH:mm:sszz")

        if now() >= expiresAt:
          # if token has expried, will  notify the user
          # and redirect to `/auth/forgot-password`
          userSession.notify("The link has expired. Please, request a new one.", some("/auth/forgot-password"))
          go getAuthForgotPassword # redirects to `/auth/forgot-password`

        # update the password in the database
        Models.table(Users).update({
            "password": auth.hashPassword(q["new_password"])
          }).where("id", token.getUserId()
          ).exec()

        # delete the password reset token from the database
        Models.table(UserAccountPasswordResets)
              .removeRow()
              .where("token", token.getToken()).exec()
        # update the password in the database
        userSession.notify("Password has been updated", some("/auth/login"))

  # redirects to `/auth/login`
  go getAuthLogin