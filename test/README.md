# Scenario Test

## 1. Install Required Tools and Container Images

Make sure the following tools and container images are installed:

### Docker

\* Note: Please make it executable without using sudo

```bash
$ docker --version
Docker version 28.3.3, build 980b856
```

### containerlab

```bash
$ containerlab version
  ____ ___  _   _ _____  _    ___ _   _ _____ ____  _       _
 / ___/ _ \| \ | |_   _|/ \  |_ _| \ | | ____|  _ \| | __ _| |__
| |  | | | |  \| | | | / _ \  | ||  \| |  _| | |_) | |/ _` | '_ \
| |__| |_| | |\  | | |/ ___ \ | || |\  | |___|  _ <| | (_| | |_) |
 \____\___/|_| \_| |_/_/   \_\___|_| \_|_____|_| \_\_|\__,_|_.__/

    version: 0.69.3
     commit: 49ee599b
       date: 2025-08-06T21:02:24Z
     source: https://github.com/srl-labs/containerlab
 rel. notes: https://containerlab.dev/rn/0.69/#0693
```

### uv

```bash
$ uv -V
uv 0.8.13
```

### vjunos-router

```bash
$ docker images | grep vrnetlab/juniper_vjunos-router | grep 25.2R1.9
vrnetlab/juniper_vjunos-router   25.2R1.9          6e9b1472b46b   37 minutes ago   4.18GB
```

#### how to install image

1. Get VM image from [Juniper support downloads page](https://support.juniper.net/support/downloads/)
2. Clone the vrnetlab repository from [GitHub](https://github.com/srl-labs/vrnetlab/tree/master)
3. Create vjunos-router image

## 2. Synchronize Dependencies with uv

```bash
cd <repository-root>/test
uv sync
```

## 3. Place the Target Binary

Place the binary you want to test in the appropriate location.

ex:

```bash
$ ls -la <repository-root>/test/bin
drwxrwxr-x 2 --- ---     4096 Sep  3 06:06 .
drwxrwxr-x 9 --- ---     4096 Aug 28 01:23 ..
-rw-rw-r-- 1 --- ---        2 Sep  3 06:06 .gitignore
-rwxrwxr-x 1 --- --- 24878822 Aug 31 16:51 gobgp
-rwxrwxr-x 1 --- --- 29413392 Aug 31 16:42 gobgpd
-rwxrwxr-x 1 --- --- 16308672 Sep  2 09:46 pola
-rwxrwxr-x 1 --- --- 18156563 Sep  2 13:16 polad
```

## 4. Run the Test

Execute the test using the appropriate command or script.

\* Note: Make sure to run `uv run pytest` with the `-s` option. Otherwise, the test fail.

```bash
uv run pytest -s
```
