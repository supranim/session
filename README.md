<p align="center">
  Auth & Session Management for Supranim applications.<br>
  Login/Register/Logout &bullet; Cookie-based sessions &bullet;<br>
  Flash messages &bullet; CSRF protection &bullet; Session cleanup
</p>

<p align="center">
  <code>nimble install supranim_session</code>
</p>

<p align="center">
  <a href="https://supranim.github.io/session/">API reference</a><br>
  <img src="https://github.com/supranim/session/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/supranim/session/workflows/docs/badge.svg" alt="Github Actions">
</p>

## Features
- Works with [Ozark ORM](https://github.com/openpeeps/ozark)
- Supranim Service for managing user sessions in Supranim applications
- Cookie-based session management
- Support for flash messages (temporary messages that persist across redirects)
- CSRF protection for secure form submissions
- Session cleanup to remove expired sessions from the database

## Setup Supranim Session

> **Quick start:** the [Supranim Starter Kit](https://github.com/supranim/starterkit) is a
> boilerplate Supranim application that already sets up the `SessionService` — including the
> service provider, auth middleware, controllers and Tim templates shown below. The rest of this
> guide explains how to wire Supranim Session into an existing Supranim application.

### 1. Install the package

```bash
nimble install supranim_session
```

### 2. Create the service provider

Create `src/service/provider/session.nim`:

```nim
import pkg/supranim_session/service/session
export session
```

This defines the `HttpSession` singleton service. Sessions are persisted using
[Ozark ORM](https://github.com/openpeeps/ozark), so your application needs a database provider
(providing `withDBPool`) and `Users` + `UserSessions` models — see `src/model/user.nim` in the
Starter Kit.

### 3. Auth middleware

Create `src/service/middleware/auth.nim` to check that the user is authenticated:

```nim
import pkg/supranim/middleware
import ../provider/session

newMiddleware authenticate:
  ## Checks if the user is authenticated. If not, redirects to the login page.
  withSession do:
    if userSession.isAuthenticated():
      next() # continue to the next middleware
  abort("/auth/login") # redirects to `GET /auth/login` page
```

Protect routes in `src/routes.nim`:

```nim
get "/account" {.middleware: [authenticate].}
```

### 4. Prepared controller handlers

`supranim_session` ships prepared handlers for the whole auth flow (`login`, `register`,
`forgot`). Wire them up in a controller, e.g. `src/controller/auth.nim`:

```nim
import pkg/supranim/[core/paths, controller]
import pkg/supranim_session/controller/[login, register, forgot]

import ../service/provider/[db, session, tim]

ctrl getAuthLogin:
  ## GET handler renders authentication page
  login.getLogin(getHomepage)

ctrl postAuthLogin:
  ## POST handle authentication requests
  login.postLogin(getHomepage)

ctrl getAuthLogout:
  ## GET handle for logging out.
  ## This will clear the session and redirect to the login page.
  login.getLogout(getAuthLogin)

ctrl getAuthRegister:
  ## GET handle for rendering the registration page
  register.getRegister()

ctrl postAuthRegister:
  ## POST handle for registering a new user
  register.postRegister()

ctrl getAuthForgotPassword:
  ## GET handler renders the forgot password page
  forgot.getForgotPassword(getAuthForgotPassword)

ctrl postAuthForgotPassword:
  ## POST handle for forgot password requests
  forgot.postForgotPassword(getAuthForgotPassword)

ctrl getAuthResetPassword:
  ## GET renders the `/auth/reset-password` page
  forgot.getResetPassword(getAuthResetPassword)

ctrl postAuthResetPassword:
  ## POST handle for reset password requests
  forgot.postResetPassword()
```

Register the routes in `src/routes.nim`:

```nim
group "/auth":
  (get, post) -> "/login"
  (get, post) -> "/forgot-password"
  (get, post) -> "/reset-password"
  (get, post) -> "/register"
  get "/logout"
```

### 5. Tim templates

The prepared handlers render Tim views and expect the `notifications` and `csrf` locals.
Create `src/templates/views/auth/login.timl`:

```timl
macro showNotifications() =
  for $msg in $this["notifications"]:
    div.alert.alert-info.border-0 > p.mb-0: $msg

@showNotifications()

form method="POST" action="/auth/login"
  div.mb-3
    input.form-control name="email" type="email" placeholder="Email address"
  div.mb-3
    input.form-control name="password" type="password" placeholder="Password"

  input type="hidden" name="csrf" value=$this["csrf"]

  button.btn.btn-primary: "Log in to your account"
```

The Starter Kit provides complete templates for `login`, `register`, `forgot` and `reset`
under `src/templates/views/auth/`.

### 6. Use sessions in your own controllers

Use the `withSession` template inside any controller to access the current session. If no
session exists yet, one is created for you and its cookie is sent with the response:

```nim
import pkg/supranim/[core/paths, controller]
import ../service/provider/[db, session, tim]

ctrl getDashboard:
  ## A protected page that renders data from the authenticated user.
  withSession do:
    if not userSession.isAuthenticated():
      go getAuthLogin # redirects to `/auth/login`
    withDBPool do:
      let
        userSessionRow = Models.table(UserSessions)
                                .select(["user_id"])
                                .where("session_id", userSession.getId())
                                .getAll().first()
        user = Models.table(Users)
                      .select(["email", "name"])
                      .where("id", userSessionRow.getUserId())
                      .getAll().first()
      render("dashboard", local = &*{
        "user": user,
        "csrf": userSession.genCSRF("/account/profile"),
        "notifications": userSession.getNotifications(req.getUriPath)
      })
```

Send flash notifications that persist across redirects:

```nim
ctrl postDashboard:
  ## Saves the user's changes and redirects back with a flash message.
  withSession do:
    userSession.notify("Your changes have been saved")
  go getDashboard # redirects to `/dashboard`
```

### 7. Configure the session

Tweak the defaults exposed by the `HttpSession` config, e.g. during app boot:

```nim
import std/times
import ../service/provider/session

proc configureSession*() =
  session().config.expiration = initDuration(days = 7)
  session().config.session_cookie.name = "app_ssid"
  session().config.authentication.enableRememberMe = true
  session().config.authentication.enableMultipleSessions = false
```

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/supranim/session/issues)
- 👋 Wanna help? [Fork it!](https://github.com/supranim/session/fork)

### 🎩 License
MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright &copy; OpenPeeps & Contributors &mdash; All rights reserved.