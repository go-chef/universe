universe
--------

An experimental standalone /universe endpoint.

Installation
------------

`go get -t github.com/go-chef/universe`

*Important:* Right now, this program depends on goiardi libs from an unreleased
version of goiardi. After getting the dependencies, go into 
$GOPATH/src/github.com/ctdk/goiardi and run `git checkout 1.0.0-dev`, then run
`go install github.com/ctdk/goiardi`, then rebuild universe with `go install
github.com/go-chef-universe`.

Configuration
-------------

Currently it uses all the same options as goiardi. Unfortunately at the moment
universe will only work with the in-memory data storage saved to disk, because
the goiardi work for organizations isn't far enough along for it to work with
the databases. To actually have any cookbooks, you'll need to run goiardi in
in-memory mode with disk persistence, load up cookbooks, and then shut it down
and run universe with the same command-line arguments.

Important Noteworthy Notes
--------------------------

* As mentioned, this depends on a development branch of goiardi.
* Some functions from goiardi were copy-pasted into here that turned out to be
  more broadly useful. Soon on the goiardi side they will be moved into their
  own library, but for testing it out it's staying this way for a bit.
* As also mentioned previously, it only works with the in-mem datastore because
  goiardi+orgs isn't far enough along yet to support the databases. All in good
  time.
