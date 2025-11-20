If you want to keep using a mirror to speed up installs/builds, you can keep a config like the following in `~/.cargo/config.toml` (override it at publish time via CLI flags):

```/dev/null/cargo_config.toml#L1-12
# Use rsproxy's sparse mirror to speed up everyday dependency downloads
[source.crates-io]
replace-with = "rsproxy-sparse"

[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"

# You can also configure git source mirrors or other items if needed
```

2. Log in to crates.io using the recommended method

- The warning says “cargo login <token>” is deprecated; it’s recommended to read the token from stdin.
- Since you replaced the registry with a mirror, both login and publish must explicitly target the crates.io registry: --registry crates-io

```/dev/null/shell.sh#L1-3
# Pass your crates.io token via stdin and target the crates.io registry
printf "%s" "YOUR_CRATES_IO_TOKEN" | cargo login --registry crates-io
```

3. Publish via crates.io (bypassing the mirror)

- The error message already points it out: you need to add --registry crates-io
- Do a dry-run first, then publish for real

```/dev/null/shell.sh#L1-4
# Package contents check
cargo publish --dry-run --registry crates-io

# If everything looks good, publish for real
cargo publish --registry crates-io
```

Additional tips

- You don’t have to store the token persistently; you can pass it only when publishing:

```/dev/null/shell.sh#L1-1
cargo publish --registry crates-io --token "YOUR_CRATES_IO_TOKEN"
```

- Your crates.io account email must be verified, otherwise the publish will fail.
- If you keep the mirror replacement, [source.crates-io] replace-with will affect default registry resolution. As long as you pass --registry crates-io for login and publish, you’ll bypass the mirror and talk to crates.io directly.
- Also apply the Cargo.toml metadata recommendations (description, license, readme, repository, keywords, categories, include, etc.). These affect the quality of the package and the likelihood of a smooth publish. Before publishing you can run:

```/dev/null/shell.sh#L1-2
cargo package --list
cargo publish --dry-run --registry crates-io
```

## User

[@crates.md](file:///Users/jerrychir/Desktop/dev/coding/ooiai/wxkefu-rs/crates.md) 翻译英文

## Assistant

Here’s the English translation of crates.md:

If you want to continue using a mirror to speed up installs/builds, you can keep a configuration like the following in `~/.cargo/config.toml` (you can override it at publish time via CLI flags):

```/dev/null/cargo_config.toml#L1-12
# Use rsproxy's sparse mirror to speed up everyday dependency downloads
[source.crates-io]
replace-with = "rsproxy-sparse"

[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"

# You can also configure git source mirrors or other items if needed
```

2. Log in to crates.io using the recommended method

- The warning says “cargo login <token>” is deprecated; it’s recommended to read the token from stdin.
- Additionally, since you replaced the registry with a mirror, both login and publish must explicitly specify the crates.io registry: --registry crates-io

```/dev/null/shell.sh#L1-3
# Pass your crates.io token via stdin and specify the crates.io registry
printf "%s" "YOUR_CRATES_IO_TOKEN" | cargo login --registry crates-io
```

3. Publish via crates.io (bypassing the mirror)

- The error message already points it out: you need to add --registry crates-io
- Do a dry-run first, then publish for real

```/dev/null/shell.sh#L1-4
# Package contents check
cargo publish --dry-run --registry crates-io

# If everything looks good, publish for real
cargo publish --registry crates-io
```

Additional tips

- You don’t have to store the token persistently; you can pass it only when publishing:

```/dev/null/shell.sh#L1-1
cargo publish --registry crates-io --token "YOUR_CRATES_IO_TOKEN"
```

- Your crates.io account email must be verified, otherwise the publish will fail.
- If you keep the mirror replacement, [source.crates-io] replace-with will affect default registry resolution. As long as you pass --registry crates-io for login and publish, you’ll bypass the mirror and connect directly to crates.io.
- Also complete the Cargo.toml metadata I suggested earlier (description, license, readme, repository, keywords, categories, include, etc.), as these affect package quality and the likelihood of a smooth publish. Before publishing you can run:

```/dev/null/shell.sh#L1-2
cargo package --list
cargo publish --dry-run --registry crates-io
```
