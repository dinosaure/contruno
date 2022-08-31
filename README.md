<h1 align="center">Contruno</h1>
<h4 align="center">A TLS termination proxy as an unikernel</h4>
<hr>

<p align="center">
<img src="https://github.com/dinosaure/contruno/blob/main/img/uno.jpg?raw=true">
</p>

`contruno` is a TLS termination proxy is a proxy server that acts as an
intermediary point between client and server applications, and is used to
establish TLS tunnels with let's encrypt certificates.

From a Git repository which contains TLS certificates and private keys
delivered by let's encrypt, the user is able launch into its private network a
simple HTTP server. `contruno` does the bridge between the client which
initiates a TLS tunnel with a specific certificate from the Git repository and
its HTTP server.

`contruno` handles expiration of certificates and do the let's encrypt
challenge (the HTTP challenge) when one of is expired. Then, it renegociates
current connections with the new certificate and save it (with its private key)
into the Git repository.

If `contruno` shutdowns, you can restart it and, from the same Git repository,
it will restart the TLS termination proxy with all current certificates.

## How to use it?

**status**: experimental

`contruno` wants few informations:
- The Git repository
- The SSH seed to generate (via _fortuna_) the private SSH key
- A password
- If you want to use production ready certificates or not
- Email, certificate seed and account seed (optional)

The Git repository should be well formed. A tool exists, `contruno.add` to put
a new certificate (with its private key) into the Git repository and signals
the unikernel (via the password) to reload certificates.

### How to compile the project?

The `contruno` repository provides three things: a `contruno` OCaml library, a
`contruno.add` binary (used to configure the unikernel), and the `contruno`
unikernel itself.

First, let's install the library and binary as opam packages:
```sh
git clone https://github.com/dinosaure/contruno && cd contruno
opam pin -y .
```

Building the unikernel requires mirage and dune:
```
opam install 'mirage>=4.0' 'dune>=3.0'
```

Next, let's build the unikernel. Due to a build system limitation, we need to
copy the sources in `unikernel/` somewhere else before building:
```sh
cp -r unikernel /tmp/ && cd /tmp/unikernel/
mirage configure -t hvt  # hvt for the KVM target
make depends
mirage build
```

And we now have a unikernel image `dist/contruno.hvt` ready to be deployed.

### How to deploy the _unikernel_?

Let's start with a simple network topology with a private network 10.0.0.0 on a
bridge `br0`:
```sh
$ cat >>/etc/network/interfaces <<EOF

auto br0
iface br0 inet static
  address 10.0.0.1
  netmask 255.255.255.0
  broadcast 10.0.0.255
  bridge_ports none
  bridge_stp off
  bridge_fd 0
  bridge_maxwait 0
EOF
$ systemctl restart networking
```

At the beginning, you need a virtual interface TAP:
```sh
# ip tuntap add mode tap tap100
# ip link set dev tap100 up
# brctl addif br0 tap100
```

In such layout, you need to "redirect" TCP/IP packets from eht0:443 to your
private IP address 10.0.0.2 (your unikernel). It's possible to do that via
`iptables`:
```sh
$ sysctl -w net.ipv4.ip_forward=1
$ iptables -A FORWARD -o br0 -m conntrack --ctstate RELATED,ESTABLISHED \
  -j ACCEPT
$ iptables -A FORWARD -i br0 ! -o br0 -j ACCEPT
$ iptables -A FORWARD -i br0 -o br0 -j ACCEPT
$ iptables -t nat -A POSTROUTING -s 10.0.0.0/24 ! -o eth0 -j MASQUERADE
$ iptables -N CONTRUNO
$ iptables -A CONTRUNO -d 10.0.0.2/32 ! -i br0 -o br0 \
  -p tcp -m tcp --dport 80 -j ACCEPT
$ iptables -A CONTRUNO -d 10.0.0.2/32 ! -i br0 -o br0 \
  -p tcp -m tcp --dport 443 -j ACCEPT
$ iptables -A FORWARD -o br0 -j CONTRUNO
$ iptables -t nat -A PREROUTING -m addrytpe --dst-type LOCAL -j CONTRUNO
$ iptables -t nat -A CONTRUNO ! -s 10.0.0.2/32 -p tcp -m tcp --dport 443 \
  -j DNAT --to-destination 10.0.0.2:443
$ iptables -t nat -A CONTRUNO ! -s 10.0.0.2/32 -p tcp -m tcp --dport 80 \
  -j DNAT --to-destination 10.0.0.2:80
```

#### How to make a simple Git repository?

`contruno` needs a Git repository to store certificates for each domains. It's
easy to create a private Git repository and, in our context, it's perfect.
Indeed, the Git repository will contains private keys, so it should only be
accessible on your private network.

We will create our own Git repository with a specific SSH public key generated
by `awa_gen_key`:
```sh
$ awa_gen_key > awa.gen.key
$ cat awa.gen.key | head -n1
seed is U01hpCOJ/MHLri7YBi7NBXqZ8TXDkVyXSb7CdGQr
# adduser git
# su git
$ cd
$ mkdir .ssh && chmod 700 .ssh
$ touch .ssh/authorized_keys && chmod 600 .ssh/authorized_keys
$ cat awa.gen.key | tail -n1 >> .ssh/authorized_keys
$ mkdir certificates.git
$ cd certificates.git
$ git init --bare
$ FIRST_COMMIT=`git commit-tree $(git write-tree) -m .`
$ git update-ref "refs/heads/master" $FIRST_COMMIT
```

So we just make a Git repository with one commit. Into the
`.ssh/authorized_keys`, you should put your SSH public key to be able to pull
and push on this local repository. The seed generated by `awa_gen_key` is
important. We will pass it to the unikernel to be able to reconstruct the SSH
private key then (and let the unikernel to `pull`/`push`).

Now, we can deploy our unikernel. At this stage, we need to keep our unikernel
alive. The usual way to do that is to use `screen` (or to _daemonize_ the
process). By this way, the unikernel still continue to run even if we are
disconnected. Then, we need to have an access to `kvm`, so the current user
needs to be a part of the `kvm` group. Finally, we will use `solo5-hvt` has our
tender to launch our unikernel:
```sh
$ usermod -aG kvm $USER
$ screen
$ solo5-hvt --net:service=tap100 contruno.hvt -- \
  --ipv4=10.0.0.2/24 \
  --ipv4-gateway=10.0.0.1 \
  --remote git@10.0.0.1:certificates.git#master \
  --pass foo \
  --production false \
  --ssh-ssh U01hpCOJ/MHLri7YBi7NBXqZ8TXDkVyXSb7CdGQr \
```

**NOTE**: We currently launched `contruno` with `--production false` which
means that `contruno` will ask only fake certificates to let's encrypt. If you
really want to deploy `contruno` and use it, you should set the option to
`true`. We use the `false` option to let you to test `contruno` without
limitations from let's encrypt (you can ask an re-ask certificates without
being banned).

Finally, we can ask a new certificate via our `contruno.add` tool:
```sh
$ contruno.add --hostname <your-hostname> --ip <private-ip-of-your-website> \
  --pass foo -r git@localhost:certificates.git#master \
  --target 10.0.0.2
```

The last command will create a fake and expired certificate which enforces
`contruno` to re-asking a new one and update the `certificates.git` Git
repository with the new one. Then, `contruno` will use it for any HTTP
requests to `<your-hostname>`.

And, voilà!
