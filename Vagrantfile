Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64" # Use Debian 12
  config.vm.box_check_update = false

  config.vm.provider "virtualbox" do |vb|
    vb.cpus = 4
    vb.memory = "4096"
  end
  config.vm.provider :libvirt do |v|
    v.cpus = 4
    v.memory = 4096
  end

  config.vm.provision "shell", inline: <<-SHELL
    # Install dependencies
    apt-get update
    apt-get install -y build-essential curl git jq llvm musl-tools podman python3 skopeo zstd

    # Test podman with:
    # podman run --rm -it docker.io/library/debian:12-slim
    if [ "$(podman --version)" != "podman version 4.3.1" ] ; then
        echo >&2 "Warning: unexpected podman version: $(podman --version)"
    fi

    if ! [ -e /home/vagrant/.cargo/bin/rustup ] ; then
        # https://www.rust-lang.org/tools/install
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /tmp/rustup-install.sh
        sudo -u vagrant sh /tmp/rustup-install.sh -y --verbose --target x86_64-unknown-linux-musl,i686-unknown-linux-musl,x86_64-unknown-none
        rm /tmp/rustup-install.sh
    fi
    sudo -u vagrant /home/vagrant/.cargo/bin/rustup component add --toolchain nightly rust-src
    sudo -u vagrant /home/vagrant/.cargo/bin/rustup target add --toolchain nightly i686-unknown-linux-musl
  SHELL
end
