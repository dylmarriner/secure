# Messaging Integration Licensing Gate

The architecture prefers a SimpleX-style asynchronous relay protocol, but the repository must not silently absorb upstream implementation code before the distribution model is chosen.

Before integrating SimpleX implementation code, choose and obtain legal review for one of:

1. an AGPL-compatible/open-source product;
2. a commercial licence or other arrangement with the relevant upstream rights holders, if available;
3. an independently implemented protocol-compatible client and independently operated infrastructure, developed without copying protected implementation code.

This is an engineering gate as well as a legal one. The `secure-messaging` boundary will be kept independent so the rest of the application is not coupled to a licensing decision.
