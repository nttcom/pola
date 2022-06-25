# Pola PCE Documentation Website
[![page-build-deployment](https://github.com/nttcom/pola/actions/workflows/pages/pages-build-deployment/badge.svg)](https://github.com/nttcom/pola/actions)

This is the source for the [Pola PCE gh-pages](https://nttcom.github.io/pola/), built using [Hugo](https://gohugo.io/) with the [Docsy](https://github.com/google/docsy) theme.

## Setting up
```sh
$ git clone https://github.com/nttcom/pola # or your fork
$ cd pola
$ git switch gh-pages
$ git submodule update --init --recursive
```

## Running Hugo server & Checking preview website
```sh
$ hugo server
# (snip)
Web Server is available at http://localhost:1313/pola/ (bind address 127.0.0.1)
Press Ctrl+C to stop
```

You can check the preview website by visit [http://localhost:1313/pola/](http://localhost:1313/pola/) in browser.

## Contributing
Please fork the repository and create a pull-request. We welcome and appreciate your contribution.
