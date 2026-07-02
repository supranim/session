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
    if unlikely(isAuth()):
      # already logged in, redirect to account page
      go getAccount
    render("auth.register", layout, local = &*{
      "notifications": userSession.getNotifications(req.getUriPath),
      "csrf": userSession.genCSRF("/auth/register")
    })

const registrationMessage* = "Thanks for registration! If this is a new account, a confirmation link will be sent to your email address. If you lost access to your account, <a href='/auth/forgot-password'>reset your password here</a>."
template postRegister*(preHook, postHook: untyped = ()) =
  ## POST handle for registering a new user
  let q {.inject.} = req.getFieldsTable().get()
  withSession do:
    if unlikely(isAuth()):
      # already logged in, redirect to account page
      go getAccount
    
    # check if registration is enabled in the session config
    if not session().config.registration.enable:
      userSession.notify("Registration is currently disabled.")
      go getAuthLogin

    # insert prehook code here
    # this may contain additional logic that should be added before
    # validating the input data
    preHook

    # validate the registration form fields
    withValidator req.getFields:
      email: tEmail""
      password: tPasswordStrength""
        # a strong password is required
      password_confirm -> callback do(input: string) -> bool:
        # ensure the password matches the confirmation password
        q["password_confirm"] == q.getOrDefault"password"
      csrf -> callback do(input: string) -> bool:
        # validate the CSRF token required for registration
        return userSession.validateCSRF("/auth/register", input)
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
      elif fields.contains("csrf"):
        userSession.notify("Invalid CSRF token. Please refresh the page and try again.")
      else:
        userSession.notify(registrationMessage)
      go getAuthRegister # get redirected to `/auth/register`

    # emit `account.register` event to handle the
    # registration request. this event is spawned in a new thread
    # to avoid blocking the request.
    event().emit("account.register", some(@[q["email"], q["password"]]))

    # insert posthook here
    postHook

    # notify the user that the account has been created
    # and a confirmation link has been sent to the given email address.
    userSession.notify(registrationMessage, some("/auth/login"))
    
    # redirect to `/auth/login`
    go getAuthLogin
