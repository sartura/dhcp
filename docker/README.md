docker for SIP Sysrepo plugin.

## build dockerfile

```
$ docker build -t sysrepo/sysrepo-netopeer2:dhcp -f Dockerfile .
```

## run dockerfile with supervisor

```
$ docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -i -t -v /opt/yang:/opt/fork --name dhcp_plugin -p 830:830 --rm sysrepo/sysrepo-netopeer2:dhcp
```

## run dockerfile without supervisor

```
$ docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -i -t -v /opt/yang:/opt/fork --name dhcp_plugin --rm sysrepo/sysrepo-netopeer2:dhcp bash
$ ubusd &
$ rpcd &
$ sysrepod
$ sysrepo-plugind
$ netopeer2-server
```
