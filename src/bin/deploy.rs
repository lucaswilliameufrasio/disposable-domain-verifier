use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const CONTAINER_PREFIX: &str = "disposable-domain-verifier";

fn main() {
    if let Err(error) = run() {
        eprintln!("deploy: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(
            "run this command in an interactive terminal; no SSH host is configured by default"
                .into(),
        );
    }

    let ssh_alias = prompt("SSH alias from ~/.ssh/config: ")?;
    if !valid_host_alias(&ssh_alias) {
        return Err("enter a valid SSH alias (no default host is configured)".into());
    }

    ensure_rootless_docker(&ssh_alias)?;
    let remote_arch_raw = remote_output(&ssh_alias, &["uname", "-m"])?;
    let remote_arch = normalize_arch(&remote_arch_raw).ok_or_else(|| {
        format!(
            "unsupported remote CPU architecture: {}",
            remote_arch_raw.trim()
        )
    })?;
    let local_arch = normalize_arch(env::consts::ARCH).ok_or_else(|| {
        format!(
            "unsupported build-machine CPU architecture: {}",
            env::consts::ARCH
        )
    })?;
    let rust_target = target_for_arch(remote_arch)?;

    let host_port = prompt("Host port for the API [9999]: ")?;
    let host_port = if host_port.is_empty() {
        "9999"
    } else {
        &host_port
    };
    let port: u16 = host_port.parse().map_err(|_| "enter a valid TCP port")?;
    if port == 0 {
        return Err("enter a valid TCP port".into());
    }

    let bind_address = prompt("Remote IPv4 bind address [127.0.0.1]: ")?;
    let bind_address = if bind_address.is_empty() {
        "127.0.0.1"
    } else {
        &bind_address
    };
    bind_address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "enter a valid remote IPv4 address")?;

    let container = format!("{CONTAINER_PREFIX}-{port}");
    let image = format!("{CONTAINER_PREFIX}:{}", git_revision()?);
    let existing = remote_output(
        &ssh_alias,
        &[
            "docker",
            "ps",
            "-a",
            "--filter",
            &format!("name=^/{container}$"),
            "--format",
            "{{.Names}}",
        ],
    )?;
    let replace_existing = !existing.trim().is_empty();
    if replace_existing {
        println!(
            "Container {container} already exists. Replacing it may interrupt its current traffic."
        );
        let answer = prompt("Replace it? [y/N] ")?;
        if answer != "y" && answer != "Y" {
            return Err("cancelled; existing container was preserved".into());
        }
    }

    println!("Building {image} for the destination architecture ({remote_arch})...");
    let binary_path = compile_binary(local_arch, remote_arch, rust_target)?;
    let context = TemporaryDirectory::create()?;
    stage_runtime_context(&context.path, &binary_path)?;
    build_image_on_destination(&ssh_alias, &image, &context.path)?;

    if replace_existing {
        remote_run(&ssh_alias, &["docker", "rm", "-f", &container])?;
    }

    remote_run(
        &ssh_alias,
        &[
            "docker",
            "run",
            "-d",
            "--name",
            &container,
            "--label",
            "com.disposable-domain-verifier.managed=true",
            "--restart",
            "unless-stopped",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--memory",
            "128m",
            "--cpus",
            "0.5",
            "--pids-limit",
            "64",
            "--publish",
            &format!("{bind_address}:{port}:9999"),
            "--env",
            "PORT=9999",
            &image,
        ],
    )?;

    let state = remote_output(
        &ssh_alias,
        &[
            "docker",
            "inspect",
            "--format",
            "{{.State.Status}}",
            &container,
        ],
    )?;
    if state.trim() != "running" {
        return Err(format!(
            "container is not running (state: {}); inspect its logs on the selected host",
            state.trim()
        )
        .into());
    }

    println!("\nContainer {container} is running on {ssh_alias}.");
    println!(
        "It listens on {bind_address}:{port}; configure a reverse proxy to forward to that address and port."
    );
    println!(
        "Verify /health-check before switching any proxy route. This command does not change DNS or a reverse proxy."
    );
    Ok(())
}

fn ensure_rootless_docker(ssh_alias: &str) -> Result<()> {
    remote_run(ssh_alias, &["true"])?;
    let security_options = remote_output(
        ssh_alias,
        &["docker", "info", "--format", "{{json .SecurityOptions}}"],
    )?;
    if !security_options.contains("name=rootless") {
        return Err("remote Docker daemon is not confirmed rootless".into());
    }
    Ok(())
}

fn compile_binary(local_arch: &str, remote_arch: &str, rust_target: &str) -> Result<PathBuf> {
    if env::consts::OS == "linux" && local_arch == remote_arch {
        run_command(
            "cargo",
            &[
                "build",
                "--release",
                "--locked",
                "--bin",
                "disposable-domain-verifier",
            ],
        )?;
        return Ok(PathBuf::from("target/release/disposable-domain-verifier"));
    }

    let zigbuild_check = Command::new("cargo")
        .args(["zigbuild", "--version"])
        .output()?;
    if !zigbuild_check.status.success() {
        return Err("cross-architecture deployment requires cargo-zigbuild and Zig; install them before retrying".into());
    }
    run_command(
        "cargo",
        &[
            "zigbuild",
            "--release",
            "--locked",
            "--target",
            rust_target,
            "--bin",
            "disposable-domain-verifier",
        ],
    )?;
    Ok(PathBuf::from(format!(
        "target/{rust_target}/release/disposable-domain-verifier"
    )))
}

fn stage_runtime_context(context: &Path, binary: &Path) -> Result<()> {
    fs::copy(binary, context.join("disposable-domain-verifier"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            context.join("disposable-domain-verifier"),
            fs::Permissions::from_mode(0o755),
        )?;
    }

    copy_directory(Path::new("assets"), &context.join("assets"))?;
    fs::write(
        context.join("Dockerfile"),
        "FROM gcr.io/distroless/cc-debian13:nonroot\n\
         WORKDIR /app\n\
         COPY --chown=nonroot:nonroot disposable-domain-verifier ./disposable-domain-verifier\n\
         COPY --chown=nonroot:nonroot assets ./assets\n\
         USER nonroot:nonroot\n\
         EXPOSE 9999\n\
         ENTRYPOINT [\"./disposable-domain-verifier\"]\n",
    )?;
    Ok(())
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_directory(&source_path, &destination_path)?;
        } else {
            fs::copy(source_path, destination_path)?;
        }
    }
    Ok(())
}

fn build_image_on_destination(ssh_alias: &str, image: &str, context: &Path) -> Result<()> {
    println!("Building the container natively on the destination host (no Docker Buildx/QEMU)...");
    let mut tar = Command::new("tar")
        .args(["-C", &context.to_string_lossy(), "-cf", "-", "."])
        .stdout(Stdio::piped())
        .spawn()?;
    let tar_stdout = tar.stdout.take().ok_or("could not open tar output")?;
    let remote_script = format!(
        "set -eu; context=$(mktemp -d); trap 'rm -rf -- \"$context\"' EXIT; tar -xf - -C \"$context\"; docker build --tag {} \"$context\"",
        shell_quote(image)
    );
    let ssh = Command::new("ssh")
        .args(["-o", "BatchMode=yes", ssh_alias, &remote_script])
        .stdin(Stdio::from(tar_stdout))
        .status()?;
    let tar_status = tar.wait()?;
    if !ssh.success() {
        return Err("remote native Docker image build failed".into());
    }
    if !tar_status.success() {
        return Err("failed to stream the Docker build context".into());
    }
    Ok(())
}

fn remote_output(ssh_alias: &str, arguments: &[&str]) -> Result<String> {
    let remote_command = arguments
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let output = Command::new("ssh")
        .args(["-o", "BatchMode=yes", ssh_alias, &remote_command])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "remote command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn remote_run(ssh_alias: &str, arguments: &[&str]) -> Result<()> {
    let remote_command = arguments
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let status = Command::new("ssh")
        .args(["-o", "BatchMode=yes", ssh_alias, &remote_command])
        .status()?;
    if !status.success() {
        return Err("remote command failed".into());
    }
    Ok(())
}

fn run_command(command: &str, arguments: &[&str]) -> Result<()> {
    let status = Command::new(command).args(arguments).status()?;
    if !status.success() {
        return Err(format!("{command} command failed").into());
    }
    Ok(())
}

fn prompt(message: &str) -> Result<String> {
    print!("{message}");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().to_owned())
}

fn git_revision() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()?;
    if !output.status.success() {
        return Err("could not determine the current Git revision".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn valid_host_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 128
        && alias.as_bytes()[0].is_ascii_alphanumeric()
        && alias
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || b"._-".contains(&character))
}

fn normalize_arch(architecture: &str) -> Option<&'static str> {
    match architecture.trim() {
        "x86_64" | "amd64" => Some("x86_64"),
        "aarch64" | "arm64" => Some("aarch64"),
        _ => None,
    }
}

fn target_for_arch(architecture: &str) -> Result<&'static str> {
    match architecture {
        "x86_64" => Ok("x86_64-unknown-linux-gnu"),
        "aarch64" => Ok("aarch64-unknown-linux-gnu"),
        _ => Err(format!("unsupported target architecture: {architecture}").into()),
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn create() -> Result<Self> {
        for attempt in 0..100 {
            let path = env::temp_dir().join(format!(
                "disposable-domain-verifier-deploy-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err("could not allocate a temporary build directory".into())
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_arch, shell_quote, target_for_arch, valid_host_alias};

    #[test]
    fn accepts_only_ssh_alias_characters() {
        assert!(valid_host_alias("vps-prod_1.example"));
        assert!(!valid_host_alias(""));
        assert!(!valid_host_alias("user@host"));
        assert!(!valid_host_alias("-oProxyCommand=bad"));
    }

    #[test]
    fn maps_supported_remote_architectures_to_rust_targets() {
        assert_eq!(normalize_arch("x86_64\n"), Some("x86_64"));
        assert_eq!(normalize_arch("aarch64"), Some("aarch64"));
        assert_eq!(normalize_arch("riscv64"), None);
        assert_eq!(
            target_for_arch("x86_64").unwrap(),
            "x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            target_for_arch("aarch64").unwrap(),
            "aarch64-unknown-linux-gnu"
        );
    }

    #[test]
    fn quotes_remote_shell_arguments() {
        assert_eq!(shell_quote("safe"), "'safe'");
        assert_eq!(shell_quote("it's safe"), "'it'\\''s safe'");
    }
}
