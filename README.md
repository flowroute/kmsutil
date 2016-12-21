# kmsutil

kmsutil exists to make encrypting and decrypting local files with an
[AWS KMS](https://aws.amazon.com/kms/) secret easy.

## Install

```sh
go get github.com/flowroute/kmsutil
govendor sync
go install
```

Alternately, you can get binary releases from Releases page on GitHub.

```sh
curl -Lo ksmutil https://github.com/flowroute/kmsutil/releases/download/0.0.3/kmsutil_linux_amd64
```

## Usage

kmsutil operates in one of two modes, `pack` or `unpack`

### pack

```sh
kmsutil pack <key_id> <file>
```

Pack mode creates a new encrypted ".box" file from the given file, using the
AWS KMS key specified.  Keys can be referenced either by their alias form
(`alias/my_key_name`) or by their raw id form `xxxxx-xxxx-xxxx-xxxxxxxxx`.

This will create a new file with the same name with `.box` appended, containing
the encrypted data plus the appropriate KMS local keys.

### unpack

```sh
kmsutil unpack <file.box>
```

Unpack mode will take the output of pack mode and recreate a copy of the
original file alongside the .box file.

### Options

```
--profile
    AWS (boto) profile to use when contacting the KMS.
--region
	AWS region to connect to for KMS.
```

By default, kmsutil will use your default boto profile (from ~/.aws/config or
equivalent) and the `us-west-2` region.  You can override either with the
appropriate flag.


## Inspiration

This tool was heavily inspired by [kmstool](https://github.com/slank/kmstool).
It was written as to not require a full python installation for use inside
lightweight docker containers.
