# Contract: User signup with email verification
slug: example-user-signup
code: src/auth/signup.py, src/api/routes/signup.py, src/auth/tokens.py
tests: tests/auth/test_signup.py, tests/integration/test_signup_db.py, tests/functional/test_signup_api.py, tests/journeys/test_signup_journey.py
owed: rate limiting per IP on the signup endpoint (follow-up contract: signup-rate-limit); localisation of verification emails
assumptions:
  - Emails are unique case-insensitively; the database enforces it with a unique index on lower(email).
  - Passwords are hashed with argon2id; the hash parameters live in config, not in code.
  - Verification tokens expire after 24 hours and are single-use.
  - The verification email is sent through the outbox table, never synchronously from the request.
  - Signup is available to all tenants; tenant assignment happens at the first login, not here.

## Unit

### Scenario: password policy rejects short passwords
- Given a candidate password of 7 characters
- When the password policy is evaluated
- Then it is rejected with reason "too short"
- And the reason does not echo the password

### Scenario: verification token is single use
- Given a freshly issued verification token for a user
- When the token is consumed once
- And the same token is presented again
- Then the second presentation is rejected as "already used"

### Scenario: email normalisation lowercases and trims
- Given the raw email "  Ada.Lovelace@Example.COM "
- When the email is normalised
- Then the stored value is "ada.lovelace@example.com"

## Integration

### Scenario: duplicate email is refused by the database
- Given a user row exists for "ada@example.com"
- When a second signup is attempted with "ADA@example.com"
- Then the insert fails on the unique index on lower(email)
- And no second user row exists
- And no outbox row was written for the second attempt

### Scenario: signup writes the user and the outbox row in one transaction
- Given an empty users table and an empty outbox table
- When a signup for "grace@example.com" is committed
- Then exactly one users row and exactly one outbox row exist
- And the outbox row references the new user id and the verification token hash

## Functional

### Scenario: POST /signup returns 201 and never returns the token
- Given a running API with a local database
- When a client POSTs {"email": "grace@example.com", "password": "correct horse battery staple"}
- Then the response is 201 with body {"status": "verification_sent"}
- And the response body and headers contain no token and no password

### Scenario: POST /signup with a malformed email returns 422
- Given a running API
- When a client POSTs {"email": "not-an-email", "password": "correct horse battery staple"}
- Then the response is 422
- And the error names the field "email" and not the submitted value

### Scenario: GET /verify consumes the token and activates the account
- Given a signed-up but unverified user with a valid token
- When the client GETs /verify?token=<token>
- Then the response is 200 with {"status": "verified"}
- And the user row is marked verified
- And a second GET with the same token returns 410

## Journey

### Scenario: a new user signs up, verifies and logs in
- Given a browser on the signup page
- When the user submits a valid email and password
- And opens the verification link from the test outbox
- And logs in with the same credentials
- Then the dashboard greets the user by email
- And the audit log shows signup, verify and login events in that order

### Scenario: a user who never verifies cannot log in and can request a new link
- Given a user who signed up 25 hours ago and never verified
- When the user tries to log in
- Then login is refused with "verify your email"
- And requesting a new verification link issues a fresh token and invalidates the expired one

### Scenario: account deletion removes every row holding the user's email
- Given a verified user with login history
- When the user deletes the account from settings
- Then no users, outbox, session or audit row contains the user's email in plain text
- And the deletion is recorded with the user id only
