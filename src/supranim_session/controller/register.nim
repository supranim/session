# A Service provider for managing HTTP Sessions
# in a Supranim application.
#
#   (c) 2025 George Lemon / Made by Humans from OpenPeeps
#   https://supranim.com | https://github.com/supranim
#   
#   Released under the MIT License.

template getRegister*(layout = "base") =
  ## GET handle for rendering the registration page
  withSession do:
    render("auth.register", layout, local = &*{
      "notifications": userSession.getNotifications(req.getUriPath).get(@[]),
      "csrf": userSession.genCSRF("/auth/register")
    })

const registrationMessage* = "Thanks for registration! If this is a new account, a confirmation link will be sent to your email address. If you lost access to your account, <a href='/auth/forgot-password'>reset your password here</a>."
template postRegister* =
  ## POST handle for registering a new user
  let q = req.getFieldsTable().get()
  withSession do:
    withValidator req.getFields:
      email: tEmail""
      password: tPasswordStrength""
        # a strong password is required
      password_confirm -> callback do(input: string) -> bool:
        # ensure the password matches the confirmation password
        q["password_confirm"] == q.getOrDefault"password"
    do:
      # validation failed, set the flash message to notify
      # the user and redirect back to `/auth/register`
      let fields = inputBag.getErrors.toSeq().mapIt(it[0])
      if fields.contains("email"):
        userSession.notify("The email address is not valid")
      elif fields.contains("password"):
        userSession.notify("The password is not strong enough")
      elif fields.contains("password_confirm"):
        userSession.notify("The password confirmation does not match")
      else:
        userSession.notify(registrationMessage)
      go getAuthRegister # get redirected to `/auth/register`

    # emit `account.register` event to handle the
    # registration request. this event is spawned in a new thread
    # to avoid blocking the request.
    events.emitter("account.register", some(@[req.getFields[0][1], req.getFields[1][1]]))
    
    # notify the user that the account has been created
    # and a confirmation link has been sent to the given email address.
    userSession.notify(registrationMessage, some("/auth/login"))
    
    # redirect to `/auth/login`
    go getAuthLogin
