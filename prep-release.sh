#!/bin/bash
# Use this script to generate packages for public release of Bit-Twist.
# Packages in release directory are to be uploaded manually to SourceForge and GitHub.

VERSION=$(cat "VERSION")

rm -rf bittwist-linux-${VERSION} bittwist-bsd-${VERSION} bittwist-macos-${VERSION} bittwist-windows-${VERSION}
mkdir -p bittwist-linux-${VERSION}/src bittwist-bsd-${VERSION}/src bittwist-macos-${VERSION}/src bittwist-windows-${VERSION}/src/include/net

chmod -R u+rw .
chmod -R go-w .

cp -R "Makefile" "bittwist-linux-${VERSION}/"
cp -R "Makefile" "bittwist-bsd-${VERSION}/"
cp -R "Makefile" "bittwist-macos-${VERSION}/"
cp -R "Makefile.windows" "bittwist-windows-${VERSION}/Makefile"

files=(".clang-format" "AUTHORS" "BUGS" "CHANGES" "COPYING" "README.md" "VERSION" "doc")
for file in "${files[@]}"; do
    cp -R "$file" "bittwist-linux-${VERSION}/"
    cp -R "$file" "bittwist-bsd-${VERSION}/"
    cp -R "$file" "bittwist-macos-${VERSION}/"
    cp -R "$file" "bittwist-windows-${VERSION}/"
done

files=("tinymt")
for file in "${files[@]}"; do
    cp -R "src/$file" "bittwist-linux-${VERSION}/src/"
    cp -R "src/$file" "bittwist-bsd-${VERSION}/src/"
    cp -R "src/$file" "bittwist-macos-${VERSION}/src/"
    cp -R "src/$file" "bittwist-windows-${VERSION}/src/"
done

files=(
    "token_bucket.c"
    "token_bucket.h"
    "template_pcap.c"
    "template_pcap.h"
    "bittwist.c"
    "bittwist.h"
    "bittwiste.c"
    "bittwiste.h"
)
for file in "${files[@]}"; do
    cp "src/$file" "bittwist-linux-${VERSION}/src/"
    cp "src/$file" "bittwist-bsd-${VERSION}/src/"
    cp "src/$file" "bittwist-macos-${VERSION}/src/"
    cp "src/$file" "bittwist-windows-${VERSION}/src/"
done

cp src/def.h bittwist-linux-${VERSION}/src/
cp src/def.h bittwist-bsd-${VERSION}/src/
cp src/def.h bittwist-macos-${VERSION}/src/

cp src/def.h bittwist-windows-${VERSION}/src/include/
cp src/include/ifaddrs.h bittwist-windows-${VERSION}/src/include/
cp src/include/net/if_dl.h bittwist-windows-${VERSION}/src/include/net/
# Copied from C:\WINDOWS\system32\ (after installing https://www.cygwin.com/setup-x86_64.exe)
cp src/cygwin1.dll bittwist-windows-${VERSION}/src/
# Copied from https://npcap.com/dist/npcap-sdk-1.13.zip
cp -R npcap-sdk bittwist-windows-${VERSION}/

# Precompiled executables for Windows (these must be copied manually from Windows system prior to running this script)
cp -R src/bittwist.exe bittwist-windows-${VERSION}/src/
cp -R src/bittwiste.exe bittwist-windows-${VERSION}/src/

destinations=("bittwist-linux-${VERSION}/tests/" "bittwist-bsd-${VERSION}/tests/" "bittwist-macos-${VERSION}/tests/" "bittwist-windows-${VERSION}/tests/")
for destination in "${destinations[@]}"; do
    rsync -aHAXxv --numeric-ids \
        --exclude=".gitignore" \
        --exclude=".idea" \
        --exclude=".pytest_cache" \
        --exclude="__pycache__" \
        --exclude="format.sh" \
        --exclude="freeze.sh" \
        --exclude="pcap/out.pcap" \
        --exclude="venv" \
        tests/ "${destination}"
done

if [ -d ../sourceforge/htdocs/doc/ ]; then
    cp doc/*.html ../sourceforge/htdocs/doc/
fi

rm -rf release && mkdir release

tar -czvf release/bittwist-linux-${VERSION}.tar.gz bittwist-linux-${VERSION}
tar -czvf release/bittwist-bsd-${VERSION}.tar.gz bittwist-bsd-${VERSION}
tar -czvf release/bittwist-macos-${VERSION}.tar.gz bittwist-macos-${VERSION}
zip -r release/bittwist-windows-${VERSION}.zip bittwist-windows-${VERSION}

cd release

sha256sum bittwist-linux-${VERSION}.tar.gz > bittwist-linux-${VERSION}.tar.gz.sha256sum
sha256sum bittwist-bsd-${VERSION}.tar.gz > bittwist-bsd-${VERSION}.tar.gz.sha256sum
sha256sum bittwist-macos-${VERSION}.tar.gz > bittwist-macos-${VERSION}.tar.gz.sha256sum
sha256sum bittwist-windows-${VERSION}.zip > bittwist-windows-${VERSION}.zip.sha256sum

cd ..

chmod -R u+rw .
chmod -R go-w .
