=== Login by BindID ===

Contributors: Transmit Security
Tags: passwordless, login, authentication, multi-factor, user registration, MFA, BindID, 2-factor, 2FA
Requires at least: 5.7
Tested up to: 6.0
Stable tag: 1.0.12
license: GPL-2.0+

== Description ==

Login by BindID provides a seamless, passwordless login experience for your WordPress websites.

As a site developer you:
* Receive a one-click installation solution with strong passwordless authentication for your site.
* Save costs and resources that would have been used to build security and authentication features.
* Protect against all password-based attacks.

Your users enjoy:
* Fast and frictionless website registration.
* An effortless and comfortable sign-in experience every time.
* No credentials or passwords to remember which means zero password resets.
* Passwordless multi-factor authentication that only requires the user and their personal device.
* Account protection against identity theft.

BindID demo video - [A Better Way To Authenticate: BindID](https://www.youtube.com/watch?v=poH4e1ENMkU).

Please see our [how-to guide](https://developer.bindid.io/docs/guides/external_integrations/topics/integratingWordPress/integrating_with_wordpress) for more details on bringing passwordless experiences to your site.

== Installation ==

* To use this plugin you will need to have a free or paid BindID tenant. Go [here](https://www.transmitsecurity.com/developer?utm_signup=wp_store#try) to create one.
* Follow the [instructions](https://developer.bindid.io/docs/guides/external_integrations/topics/integratingWordPress/integrating_with_wordpress) to integrate your WordPress site with BindID passwordless login.

== FAQ ==

= What level of security does BindID provide? =

BindID uses FIDO-based biometrics combined with the common OpenID Connect (OIDC) standard to provide secure authentication to web services. 

= Can the login experience be customized to match my site? =

The login button provided by BindID is fixed. At this time, customization is not supported.

= What would be the experience for existing users after BindID plugin is enabled in my WordPress website? = 

BindID users are associated with subscribers using their email address, which is included in the BindID ID token for every login. New subscribers are added to the WordPress site when a user logs in using BindID and their email address doesn’t correspond to an existing user.


== Screenshots ==

1. Intro: Instant login and registration with BindID
2. Step 1: Just invoke the mobile device
3. Step 2: Simply login with BindID the app-less mobile authenticator
4. Step 3: The identity process is now complete and your user is authenticated
5. BindID by Transmit Security

== Changelog ==

= 1.0.8 =

* First release.

= 1.0.9 =

* Fix "View Details" content.

= 1.0.10 =

* Changed tenant registration to the transmitsecurity site.

= 1.0.11 =

* Added support for running the plugin in a BindID production environment.

= 1.0.12 =

* Wordpress 6.0 compatibility.