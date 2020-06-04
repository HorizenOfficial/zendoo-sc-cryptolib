#!/bin/bash
set -e

# Add local zenbuilder user
# Either use LOCAL_USER_ID:LOCAL_GRP_ID if set via environment
# or fallback to 9001:9001

USER_ID=${LOCAL_USER_ID:-2000}
GRP_ID=${LOCAL_GRP_ID:-2000}

getent group zenbuilder > /dev/null 2>&1 || groupadd -g $GRP_ID zenbuilder
id -u zenbuilder > /dev/null 2>&1 || useradd --shell /bin/bash -u $USER_ID -g $GRP_ID -o -c "" -m zenbuilder

LOCAL_UID=$(id -u zenbuilder)
LOCAL_GID=$(getent group zenbuilder | cut -d ":" -f 3)

if [ ! "$USER_ID" == "$LOCAL_UID" ] || [ ! "$GRP_ID" == "$LOCAL_GID" ]; then
    echo "Warning: User zenbuilder with differing UID $LOCAL_UID/GID $LOCAL_GID already exists, most likely this container was started before with a different UID/GID. Re-create it to change UID/GID."
fi

echo "Starting with UID/GID: $LOCAL_UID:$LOCAL_GID"

export HOME=/home/zenbuilder

# Fix ownership recursively
chown -RH zenbuilder:zenbuilder /build

# Get Rust
curl https://sh.rustup.rs -sSf | gosu zenbuilder bash -s -- -y
gosu zenbuilder echo 'source $HOME/.cargo/env' >> $HOME/.bashrc
export PATH="/home/zenbuilder/.cargo/bin:${PATH}"


# Set Rust
gosu zenbuilder /home/zenbuilder/.cargo/bin/rustup target add x86_64-pc-windows-gnu

#Add maven settings
gosu zenbuilder bash -c "mkdir -p $HOME/.m2 && cp /build/.travis.settings.xml $HOME/.m2/settings.xml"

exec gosu zenbuilder "$@"

