# How to run tests (and linter) in Docker
```
make docker-test
```

Or, if you want to play inside the container:
```
make docker-enter
```

And there, for example:
```
python3 -m pyte
```

# How to prepare portable version manually
```
make portable
```

# How to build a new DEB/RPM/TGZ package with a stripped (Collectors only) artifact
```
make stripped_deb
make stripped_rpm
make stripped_tgz
```

# How to build full (Collectors and Analyzers) relocatable version
```
make full
```

# How to build full (Collectors and Analyzers) relocatable version and package it into a tarball
```
make full_tgz
```

# How to clean
```
make clean
make clean_rpm
make clean_deb
make clean_tgz
```

# How publish a new release
1. Update version files `dist/common/{major,minor}` in the `master` branch.
2. Create a new release with a tag according to values set in (1), e.g. `scylla-doctor-v4.2`.
3. The moment a new release is published new versioned artifacts are going to be uploaded
   to ScyllaDB's S3 bucket and on downloads.scylladb.com. The publish workflows verify
   that the release tag matches `dist/common/{major,minor}` before publishing anything.


