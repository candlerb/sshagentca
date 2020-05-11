**This is a fork of https://github.com/rorycl/sshagentca**

# sshagentca

version 0.0.5-candlerb : 10 May 2020

A proof-of-concept project to add ssh user certificates to forwarded ssh
agents using go's ssh packages.

This project is for testing purposes and has not been security audited.

Running the server:

    sshagentca -h
    sshagentca -t <privatekey> -c <caprivatekey>
               [-i <ipaddress>] [-p <port>] settings.yaml

Example client usage:

    # start an ssh agent and add a key
    ssh-agent > ~/.ssh/agent.env
    source ~/.ssh/agent.env
    ssh-add ~/.ssh/id_test
    <enter password>

    # assuming the public key or fingerprint to id_test is in the
    # settings.yaml file on the sshagentca server, along with the
    # certificate name and principals, and sshagentca is running on
    # 10.0.1.99: (it is important to forward the agent)
    ssh -p 2222 10.0.1.99 -A

    > acmecorp ssh user certificate service
    > 
    > welcome, bob
    > certificate generation complete
    > run 'ssh-add -l' to view
    > goodbye

    # now connect to remote server which has the ca public key and
    # principals files configured, remembering to specify "-A" to forward
    # the agent if needed, for example for sudo authentication, if configured
    ssh userthatcansudo@remoteserver -A

The login username that the client provides when connecting to `sshagentca`
is ignored - it does not have to match the `name:` in `settings.yaml`.

Certificates from `sshagentca` can be conveniently used with
[pam-ussh](https://github.com/uber/pam-ussh) to control sudo privileges
on suitably configured servers.

Please refer to the specification at PROTOCOL.certkeys at
https://www.openssh.com/specs.html and the related go documentation at
https://godoc.org/golang.org/x/crypto/ssh.

## Building

```
go get github.com/candlerb/sshagentca
```

The binary will be installed in `~/go/bin/sshagentca` by default.

## Details

The server requires an ssh private key and ssh certificate authority
private key, with password protected private keys. The server will
prompt for passwords on startup.

Each user requires `name and `user_principals` settings in
the settings yaml file, and either `authorized_key` or `fingerprint`.
If both are supplied, they must match.

The server will run on the specified IP address and port, by default
0.0.0.0:2222.

Settings are configured in the settings yaml file and include the
certificate settings such as the validity period and organisation name,
the prompt received by the client and the `user_principals` settings
noted above.

If the server runs successfully, it will respond to ssh connections that
have a public key or fingerprint listed in the settings yaml file and which have a forwarded
agent. This response will be to insert an ssh user certificate into the
forwarded agent which is signed by `caprivatekey` with the parameters
set out in `settings.yaml` and restrictions as noted below.

The inserted certificate is generated from a freshly-minted ECDSA key pair
with a P-384 curve for fast key generation.  The CA key you provide to
sign the certificate may be a different type (e.g. RSA).

Clients can authenticate to sshagentca using any key type supported by go's
`x/crypto/ssh` package.  This includes the ecdsa-sk key used with U2F
security keys, introduced in OpenSSH 8.2.  Hence you can use a physical U2F
token with an OpenSSH 8.2 client to authenticate to sshagentca, whilst the
certificates it issues will work with older versions of sshd.

## Certificate Restrictions

The project currently has no support for host certificates.

With reference to
https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
there is no support presently for customising *critical options*, and
only the standard *extensions*, such as `permit-agent-forwarding`,
`permit-port-forwarding` and `permit-pty` are permitted.

Each certificate's principals settings are taken from the principals set
out for the specific connecting client public key from the
`user_principals` settings.

The `valid after` timestamp is set according to the `duration` settings
parameter, specified in minutes.  Durations longer than 24 hours are
rejected.

## Key generation

To generate new server keys, refer to man ssh-keygen. For example:

    ssh-keygen -t rsa -b 4096 -f id_server

and specify a password. The id_server file is the private key. Certificate
authority keys are generated in the same way, although adding a comment is often
considered sensible for CA key management, e.g.:

    ssh-keygen -t rsa -b 4096 -f ca -C "CA for example.com"

and choose a password. The ca file is the private key. The ca.pub key in
this example should be used in the sshd_config file on any server for
which you wish to grant certificate-authenticated access. For example:

    TrustedUserCAKeys /etc/ssh/ca.pub

Optionally, an AuthorizedPrincipalsFile may also be configured, such as:

    AuthorizedPrincipalsFile /etc/ssh/ca_principals

This overrides OpenSSH's default certificate check, which is to require the
login username exists as one of the principals in the certificate.

When you specify AuthorizedPrincipalsFile, the user is permitted to login if
their certificate contains any of the principals listed in that file.  Be
aware that this will allow the user to login as *any* username which exists
on the server, including "root".

For more fine-grained control you can configure a script which outputs a
list of authorized principals depending on the user that is logging in:

    AuthorizedPrincipalsCommand /etc/ssh/authprinc.sh %u
    AuthorizedPrincipalsCommandUser nobody

Example:

```
#!/bin/sh -eu
echo "$1@$(hostname -f)"
echo "$1@+webserver"
echo "$1@+all"
```

The use of principals to provide "zone" based access to servers is set out at
https://engineering.fb.com/security/scalable-and-secure-access-with-ssh/ 

## Thanks

Thanks to Peter Moody for his pam-ussh announcement at
https://medium.com/uber-security-privacy/introducing-the-uber-ssh-certificate-authority-4f840839c5cc
which was the inspiration for this project, and the comments and help
from him and others on the ssh mailing list.

## License

This project is licensed under the [MIT Licence](LICENCE).

Rory Campbell-Lange 15 April 2020
