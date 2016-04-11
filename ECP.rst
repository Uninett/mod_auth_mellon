Guide to using ECP
==================

Introduction
------------

The **Enhanced Client or Proxy** (ECP) profile of SAML2

The Enhanced Client or Proxy (ECP) Profile supports several SSO use
cases, in particular:

  * Clients with capabilities beyond those of a browser, allowing them
    to more actively participate in IdP discovery and message flow.

  * Using a proxy server, for example a WAP gateway in front of a mobile
    device which has limited functionality.

  * When other bindings are precluded (e.g. where the client does not
    support redirects, or when auto form post is not possible without
    Javascript, or when the artifact binding is ruled out because the
    identity provider and service provider cannot directly communicate.

An enhanced client or proxy (ECP) is a system entity that knows how to
contact an appropriate identity provider, possibly in a
context-dependent fashion, and also supports the Reverse SOAP (PAOS)
binding.

An example scenario enabled by ECP profile is as follows: A principal,
wielding an ECP, uses it to either access a resource at a service
provider, or access an identity provider such that the service
provider and desired resource are understood or implicit. The
principal authenticates (or has already authenticated) with the
identity provider [1]_, which then produces an authentication assertion
(possibly with input from the service provider). The service provider
then consumes the assertion and subsequently establishes a security
context for the principal. During this process, a name identifier
might also be established between the providers for the principal,
subject to the parameters of the interaction and the consent of the
principal.

SAML2 Profile for ECP (Section 4.2) defines these steps for an ECP
transaction:

  1. ECP issues HTTP Request to SP
  2. SP issues <AuthnRequest> to ECP using PAOS
  3. ECP determines IdP
  4. ECP conveys <AuthnRequest> to IdP using SOAP
  5. IdP identifies principal
  6. IdP issues <Response> to ECP, targeted at SP using SOAP
  7. ECP conveys <Response> to SP using PAOS
  8. SP grants or denies access to principal

mod_auth_mellon and ECP
-----------------------

mod_auth_mellon plays the role of the SP in an ECP transaction.

mod_auth_mellon utilizes the Lasso library to provide it's SAML2
functionality. Fully functioning SAML2 ECP support in Lasso is
relatively new. When mod_auth_mellon is built it detects the presence
of SAML2 ECP in Lasso and only compiles in the ECP code in
mod_auth_mellon if it's present in Lasso.

How does mod_auth_mellon recognize a request is from an ECP client?
```````````````````````````````````````````````````````````````````

In Step 1. when the ECP client issues the HTTP Request to the SP it
**MUST** include `application/vnd.paos+xml` as a mime type in the HTTP
`Accept` header field and include an HTTP `PAOS` header specifying a
PAOS version of `urn:liberty:paos:2003-08` and an ECP service
declaration of `urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp` [2]_,
for example::

  Accept: text/html, application/vnd.paos+xml
  PAOS: ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"

If mod_auth_mellon sees this in the incoming request it knows the
client is ECP aware and capable. If authentication is required
mod_auth_mellon will initiate an ECP flow.

The role of IdP's in ECP
````````````````````````

The SAML2 ECP profile states it is the ECP client which determines the
IdP that will be used for authentication. This is in contrast to the
Web SSO flow where the SP determines the IdP. However, the ECP
protocol permits an SP to send the ECP client a list of IdP's it
trusts. It is optional if the SP sends an IDPList, if it does the ECP
client should select the IdP from the SP provided IDPList otherwise
the ECP client is free to select any IdP it wishes.

If the mellon configuration option `MellonECPSendIDPList` is true then
mod_auth_mellon will include an IDPList when it returns a PAOS
<AuthnRequest> to the ECP client.

To build the IDPList mod_auth_mellon scans it's list of loaded IdP's
selecting those which are ECP capable. To support ECP an IdP must
advertise the SingleSignOn service utilizing the SOAP binding.

ECP specific mod_auth_mellon configuration directives
`````````````````````````````````````````````````````

These configuration directives are specific to ECP:

MellonECPSendIDPList
  If `On` mod_auth_mellon will send an IdP list to the ECP client
  containing only those IdP's capable of ECP flow. The ECP client
  should select an IdP only from this list. If this option is `Off`
  no IdP list will be sent and the ECP client is free to select any
  IdP.

Example ECP client
``````````````````

To illustrate a simple ECP client based on Lasso we'll use the Lasso
Python binding (as opposed to pseudo code, Python is quite
readable). All error checking and another necessary ancillary code has
been eliminated in order to clearly illustrate only the ECP
operations.

.. code-block:: python

  import lasso
  import requests

  ecp = lasso.Ecp(server)
  session = requests.Session()

  MEDIA_TYPE_PAOS = 'application/vnd.paos+xml'
  PAOS_HEADER = 'ver="%s";"%s"' % (lasso.PAOS_HREF,lasso.ECP_HREF)

  # Step 1: Request protected resource, indicate ECP capable
  response = session.get(protected, headers={'Accept': MEDIA_TYPE_PAOS,
                                             'PAOS': PAOS_HEADER})

  # Process returned PAOS wrapped <AuthnRequest>
  ecp.processAuthnRequestMsg(response.text)

  # Post SOAP wrapped <AuthnRequest> to IdP, use Digest Auth to authenticate
  response = session.post(ecp.msgUrl,
                          data=ecp.msgBody,
                          auth=requests.auth.HTTPDigestAuth(user, password)
                          headers={'Content-Type': 'text/xml'})

  # Process returned SOAP wrapped <Assertion> from IdP
  ecp.processResponseMsg(response.text)

  # Post PASO wrapped <Assertion> to SP, response is protected resource
  response = session.post(ecp.msgUrl,
                          data=ecp.msgBody,
                          headers={'Content-Type': 'application/vnd.paos+xml'})


mod_auth_mellon internal ECP implementation notes
-------------------------------------------------


Notes on ECP vs. Web SSO flow
`````````````````````````````

Web SSO (Single Sign-On) flow is by far the most common and what
most people are familiar with when they think of SAML. The Web SSO
profile is designed so that browsers ignorant of SAML can perform
SAML authentication without modification. This is accomplished with
existing HTTP paradigms such as redirects, form posts, etc. which a
browser will process normally yielding the desired result.

ECP (Enhanced Client or Proxy) is a different SAML profile that
also accomplishes SSO (Single Sign-On). The distinction is an ECP
client is fully SAML aware and actively participates in the SAML
conversation.

Web SSO and ECP have very different flows, mod_auth_mellon must
support both flows. mod_auth_mellon is a SP (Service Provider).

IdP Selection Differences
`````````````````````````

With Web SSO the SP determines the IdP and redirects there.

With ECP the ECP client determines the IdP, the SP has no a prori
knowledge of the target IdP, although the SP may provide a
suggested list of IdP's when responding to the ECP client.

Since with ECP it is the ECP client which selects the IdP the set of
IdP's loaded into mod_auth_mellon are not relevant **except** if
`MellonECPSendIDPList` is enabled. In this case mod_auth_mellon will
filter the set of loaded IdP's and forward those IdP's supporting
SingleSignOn with the SOAP binding.

Apache request processing pipeline
``````````````````````````````````

Apache implements a request processing pipeline composed of
stages. An Apache extension module can participate in the pipeline
by asking to be called at specific stages (steps) by registering a
hook function for that stage. Final content returned to the HTTP
client in the HTTP response is generated in the "handler", one of
the final stages in the request processing pipeline.

One of the stages in the request pipeline is determining
authentication and authorization for protected resources. If a
resource is protected and the authentication and authorization
pipeline stages deny access or fail the request processing pipeline
is aborted early, a non-success HTTP response is returned, the
content handler is never reached.

With Web SSO if authentication needs to be performed a redirect will
be returned that redirects to a SAML endpoint (login) on our SP. This
in turn generates the SAML <AuthnRequest> with a redirect to the
IdP. All of this is very vanilla standard HTTP easily accommodated by
Apache's request processing pipeline which is designed to handle these
types of flows.

ECP requires special handling
`````````````````````````````

However ECP has a very different flow. When an ECP client sends a
request to the SP it includes a special HTTP headers indicating it is
ECP capable. If the SP determines the resource is protected and
authentication is needed and the client has signaled it is ECP capable
then the SP responds successfully (200) with a SAML <AuthnRequest>
wrapped in PAOS. *This is very different than conventional HTTP
request processing.* Here we have a case where there is a protected
resource that has **not** been authenticated yet the web server will
responds with an HTTP 200 success and content! One might normally
expect a HTTP 401 or redirect response for a protected resource when
there is no authenticated user. *This is clearly contrary to the
expectations of Apache's request processing pipeline.*

Reaching the Apache content handler
```````````````````````````````````

In order to be able to return a successful (HTTP 200) PAOS response
when doing the ECP we have to reach the part of Apache's request
processing pipeline that generates the response. In Apache terminology
this is called a (content) handler.

At an early stage we detect if authentication is required. For the
normal Web SSO profile we would redirect the client back to our login
endpoint which will be handled by our handler in a different
request. But for ECP the current request must proceed. We set a flag
on the request indicating ECP authentication is required. The pipeline
continues. When the pipeline reaches the authentication and
authorization stages we check the ECP flag on the request, if ECP
authentication is indicated we lie and tell the pipeline the user is
authenticated and authorized. We do this only so we can reach the
handler stage (otherwise because the request is for a protected
resource the pipeline would terminate with an error). Despite our
having forced authentication and authorization to be valid for the
protected resource the request processing pipeline *will not return the
protected resource* because we will subsequently intercept the request
in our handler before the pipeline reaches the point of returning the
protected resource.

At the handler stage
````````````````````

Once our handler is invoked it has 3 possible actions to perform:

  1. The request is for one of our SAML endpoints (e.g. login,
  logout, metadata, etc.) We dispatch to the handler for the specific
  action. We detect this case by matching the request URI to our SAML
  endpoints. We signal to the pipeline that our hook handled the request.

  2. The request is for a protected resource and needs ECP
  authentication performed. We detect this case by examining the ECP flag
  set on the request by an earlier hook function. The request URI is
  for the protected resource and has nothing to do with our SAML
  endpoints. We generate the PAOS <AuthnRequest> and respond with
  success (200) and signal to the pipeline that our hook handled the
  request. Note, we have not returned the protected resource, instead
  we've returned the PAOS request.

  3. The request has nothing to do with us, we decline to handle
  it. The pipeline proceeds to the next handler.


.. [1] The means by which a principal authenticates with an identity
       provider is outside of the scope of SAML. Typically an ECP
       client will utilize an HTTP authentication method when posting
       the <AuthnRequest> SOAP message to the IdP.

.. [2] Contrary to most HTTP headers the values in the PAOS header must
       be enclosed in double quotes. A semicolon is used to separate
       the values.
