# A Service provider for managing HTTP Sessions
# in a Supranim application.
#
#   (c) 2025 George Lemon / Made by Humans from OpenPeeps
#   https://supranim.com | https://github.com/supranim
#   
#   Released under the MIT License.

import ./supranim_session/controller/[login, register, forgot]
export login, register, forgot

## This module provides a session management service for Supranim applications.
## It defines a `SessionService` that can be used to create, manage, and clean up user sessions.
##
## The service provides controller procedures for handling user login, registration,
## password reset flows and templates for Tim Engine.
## 
## Also, it generates and manages CSRF tokens for form submissions and provides a simple API
## for storing flash notifications in the user session that can be displayed after redirects
## or form submissions.
## 
## For using this Supranim package you can take a look at the [Supranim Starter Kit](https://github.com/supranim/app)
## which is a boilerplate Supranim application that includes the necessary setup for using
## the `SessionService` along with example routes and templates for user authentication flows