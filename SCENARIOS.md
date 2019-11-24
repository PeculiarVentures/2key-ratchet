# SCENARIOS

Beyond providing an end-to-end encrypted session, the Double Ratchet and X3DH protocols enable you to keep the same session active without tearing it down. This is a particularly important property when dealing with long lived web-like sessions (think cookies).

Progressive Web Applications (PWAs) in particular can benefit from the traits offered by these protocols, with that said the utility is not limited to these cases, some use cases that might be interesting include:

| **SCENARIO**                | **DESCRIPTION**                                            |
|-----------------------------|------------------------------------------------------------|
| Collaborative Editing       | Modern web based document creation solutions often provide the ability for multiple people edit and annotate a document at once. Using a protocol suite like this enables the application to blind the server of these exchanges.                                                                                 |
| Secure Sessions Without TLS | TLS deployment is highly dependent on the WebPKI but not all scenarios can be serviced by the WebPKI. For example, when you connect to a router for the first time you do so over a clear text session, this is because your browser does not trust a CA who would issue a certificate for a private network like 192.168.0.1. A protocol suite like this could be useful in securing this session.                                                  |
| Chat and Video Conferencing  | Customer support and communicating with your friends or busineses in real time are increasingly common cases. Having a simple Javascript based library for confidential communication would make it possible for these experiences to be privacy preserving.                                                |
| File Exchange                | Though really an extension on chat and video conferencing scenario, one can utilize this protocol suite to build a solution to securely and confidentially exchange files.          |
| Authentication               | It would be possible, when cobined with [Key Transparency](https://github.com/google/key-transparency), to design a transparent authentication solution that was not dependent on the exchange of passwords. |
| Internet of Things           | You can also imagine `Internet Of Things` cases like thermostats and other IoT devices fast enough to contain an [embedable Javascript runtime](http://duktape.org/) that could benefit from being able to communicate amongst themselves without the need of a central authority.  |

In short, there are two cases where this protocol suite make sense, the first being when you want to augment SSL to limit the information exposed to an intermediary server and the second being when it is not practical to deliver a secure session via TLS.
