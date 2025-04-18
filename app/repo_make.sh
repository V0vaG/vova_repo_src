#!/bin/bash

################################
# Author: Vladimir Glayzer     #
# eMail: its_a_vio@hotmail.com #
################################

# https://earthly.dev/blog/creating-and-hosting-your-own-deb-packages-and-apt-repo/
# apt-get update
# apt-get install -y dpkg-dev gpg
clear



config_file=repo_make.conf
log_file=repo_make.log

if [ ! -f $config_file ]; then
	echo "Creating config file..."
	sleep 2
	echo 'ARCH_LIST=(amd64 arm64)
PORT='8000'
binary='0'
DELETE_APP_FOLDER='1'
from_scripts='1'
install_path='usr/bin'
deb_path='deb'
SRC='scripts'
extention_list=( '*.sh' '*.c' '*.py' '*.out')
exclude_list=('artifact.sh')
' > $config_file
fi

source $config_file

rm -rf /tmp/* "$SRC"/*.x.c ./*.spec

user=$USER
repo_path=$PWD
PORT=$1
dt=$(date '+%d/%m/%Y %H:%M:%S');
ip=$(curl ipinfo.io/ip)

echo "Public IP: $ip"
printf "Job time: $dt\n" > $log_file

if [[ "$1" == "-r" ]]; then
	echo "Deleting files..."
	rm -vrf ./apt-repo *.log pgp-key.* pgpkeys-* generate-release.sh
	exit
fi

rm -rvf ./apt-repo pgp-key.* pgpkeys-* generate-release.sh

script_list=( $(cd $SRC && ls ${extention_list[@]} ) )

for exclude_script in "${exclude_list[@]}"; do
	script_list=( "${script_list[@]/$exclude_script}" )
done

# Clean up any empty elements (in case of spaces or empty entries)
script_list=($(echo "${script_list[@]}" | tr -s ' '))

mkdir -p ./apt-repo/pool/main/

cp ./$SRC/*.deb ./apt-repo/pool/main/

set_version(){
	# echo "setting version: $version to file: $1"
	sed -i "s/^version='[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'/version='$version'/" ./$SRC/$1
}

install_compiler(){
  echo "Checking if $1 is installed"
  if command -v $1 >/dev/null 2>&1; then
    echo "$1 is already installed."
    return 0
  else
    echo "$1 is not installed."
     apt-get update
    if [[ $1 == 'pyinstaller' ]]; then
       apt install python3-pip -y
      pip install pyinstaller
    else
       apt-get install -y $1
    fi
  fi
}

make_pack(){
  echo "Packing: $1"
	printf "Creating pakge:  $alias v$version\n" >> $log_file
	mkdir -p "${alias%.*}_${version}_$architecture/$install_path"
	if [[ $extension == 'c' || $binary == '1' || $3 == '-p' ]]; then
	  cp -p /tmp/tmp_app.out "${alias%.*}_${version}_$architecture/$install_path/$alias"
	else
	  cp -p $SRC/$1 "${alias%.*}_${version}_$architecture/$install_path/$alias"
	fi
	mkdir -p "${alias%.*}_${version}_$architecture/DEBIAN"

	echo "Package: $alias
Version: $version
Command: $alias
Architecture: $architecture
Maintainer: Vladimir Glayzer
Homepage: http://example.com
eMail: its_a_vio@hotmail.com
Description: ${alias%.*}" > "${alias%.*}_${version}_$architecture/DEBIAN/control"

	echo "chmod 777 /$install_path/$alias
	mkdir -p ~/script_files" > "${alias%.*}_${version}_$architecture/DEBIAN/postinst"

	chmod 775 "${alias%.*}_${version}_$architecture/DEBIAN/postinst"

	dpkg --build ./${alias%.*}_${version}_$architecture

    #cp "${alias%.*}_${version}_$architecture.deb" "deb_pkg"
	mv "${alias%.*}_${version}_$architecture.deb" "./$2/${alias%.*}_${version}_$architecture.deb"

	if [[ $DELETE_APP_FOLDER = '1' ]]; then
		rm -r ${alias%.*}_${version}_${architecture}  ###################
	fi
}

compile(){
  rm /tmp/*
  echo "compiling $1"
  if [[ $extension = 'c' ]]; then
    gcc $SRC/$1 -o /tmp/tmp_app.out
  elif [[ $extension = 'py' ]]; then
    install_compiler python3
    install_compiler pyinstaller
    pyinstaller --onefile --distpath /tmp --workpath /tmp/py/work $SRC/$1
    mv /tmp/${alias}_${version} /tmp/tmp_app.out
  elif [[ $extension == 'sh' || $compile_sh == '1' ]]; then
    install_compiler shc
  	shc -f "$SRC"/"$1" -o /tmp/tmp_app.out
  fi

  architecture=$(dpkg --print-architecture)
  if [[ $2 = '-p' ]]; then
    echo "1111111111111111111"
    make_pack /tmp/tmp_app.out ${src_deb_path} '-p'
  else
    make_pack /tmp/tmp_app.out ${apt_deb_path}
  fi
}

file_source(){
  desc='N/A'
  alias='N/A'
  version='N/A'
  architecture='N/A'

  filename=$(basename -- "$1")
  extension="${filename##*.}"
  filename="${filename%.*}"
  name_list=($(echo $filename | tr "_" " "))
  alias=${name_list[0]}
  version=${name_list[1]}
  if [[ $extension == 'sh' || $extension == 'py' ]]; then
  	architecture='all'
  else
    architecture=$(dpkg --print-architecture)
  fi
  echo "Source file: "$1", alias: $alias, version: $version, arch: $architecture"
  set_version $1
}

for ARCH in ${ARCH_LIST[@]}; do
	mkdir -p ./apt-repo/dists/stable/main/binary-$ARCH
done

if [[ $from_scripts == '1' ]]; then
  for file in "${script_list[@]}"; do
    file_source "$file"
    if [[ $1 = '-p' ]]; then
      if [[ ! -d $src_deb_path ]]; then
        mkdir "$src_deb_path"
      fi
      architecture=$(dpkg --print-architecture)
      if [[ ! -f "./${src_deb_path}/${alias%.*}_${version}_${architecture}.deb" ]]; then
        compile "$file" '-p'
      fi
    elif [[ $extension == 'c' || $binary == '1' ]]; then
      compile "$file"
    else
      make_pack "$file" "${apt_deb_path}"
    fi
  done
fi

if [[ $1 = '-p' ]]; then
  echo "Finish packing to $src_deb_path, exiting..."
  exit
fi

if [[ -d "$src_deb_path" && $from_deb = '1' ]]; then
  cp ./${src_deb_path}/*.deb "$apt_deb_path"
fi

# Creating an apt Repository
for ARCH in ${ARCH_LIST[@]}; do
	echo "Creating repo for $ARCH"
	cd $repo_path/apt-repo && dpkg-scanpackages --arch $ARCH pool/ > dists/stable/main/binary-$ARCH/Packages
	cat dists/stable/main/binary-$ARCH/Packages | gzip -9 > dists/stable/main/binary-$ARCH/Packages.gz
done

echo '#!/bin/sh
set -e

do_hash() {
    HASH_NAME=$1
    HASH_CMD=$2
    echo "${HASH_NAME}:"
    for f in $(find -type f); do
        f=$(echo $f | cut -c3-) # remove ./ prefix
        if [ "$f" = "Release" ]; then
            continue
        fi
        echo " $(${HASH_CMD} ${f}  | cut -d" " -f1) $(wc -c $f)"
    done
}

cat << EOF
Origin: Example Repository
Label: Example
Suite: stable
Codename: stable
Version: 1.0
Architectures: $architecture
Components: main
Description: An example software repository
Date: $(date -Ru)
EOF
do_hash "MD5Sum" "md5sum"
do_hash "SHA1" "sha1sum"
do_hash "SHA256" "sha256sum"
' > $repo_path/generate-release.sh && chmod +x $repo_path/generate-release.sh

cd $repo_path/apt-repo/dists/stable
$repo_path/generate-release.sh > Release

# Signing apt Repository With GPG
echo "%echo Generating an example PGP key
Key-Type: RSA
Key-Length: 4096
Name-Real: VOVA
Name-Email: its_a_vio@hotmail.com
Expire-Date: 0
%no-ask-passphrase
%no-protection
%commit" > /tmp/vova_repo-pgp-key.batch

export GNUPGHOME="$(mktemp -d $repo_path/pgpkeys-XXXXXX)"
gpg --no-tty --batch --gen-key /tmp/vova_repo-pgp-key.batch
ls "$GNUPGHOME/private-keys-v1.d"
gpg --list-keys
gpg --armor --export its_a_vio@hotmail.com > $repo_path/pgp-key.public
cat $repo_path/pgp-key.public | gpg --list-packets
gpg --armor --export-secret-keys its_a_vio@hotmail.com > $repo_path/pgp-key.private
export GNUPGHOME="$(mktemp -d $repo_path/pgpkeys-XXXXXX)"
gpg --list-keys
cat $repo_path/pgp-key.private | gpg --import
gpg --list-keys

cat $repo_path/apt-repo/dists/stable/Release | gpg --default-key its_a_vio@hotmail.com -abs > $repo_path/apt-repo/dists/stable/Release.gpg

cat $repo_path/apt-repo/dists/stable/Release | gpg --default-key its_a_vio@hotmail.com -abs --clearsign > $repo_path/apt-repo/dists/stable/InRelease

cd $repo_path && ls

 gpg --no-default-keyring --keyring gnupg-ring:/etc/apt/trusted.gpg.d/vova_repo.gpg --import $repo_path/pgp-key.public

# To add repo
# echo 'deb [arch=all] http://127.0.0.1:$PORT/apt-repo stable main' |  tee /etc/apt/sources.list.d/vova_repo.list

# To add signed repo
# echo 'deb [arch=all signed-by=$repo_path/pgp-key.public] http://127.0.0.1:$PORT/apt-repo stable main' |  tee /etc/apt/sources.list.d/vova_repo.list

echo '################################################################
To add repo: echo 'deb [arch=all] http://$ip:$PORT/apt-repo stable main' |  tee /etc/apt/sources.list.d/vova_repo.list

To edit repo:  nano /etc/apt/sources.list.d/vova_repo.list


To update:  apt-get update --allow-insecure-repositories

To upgrade:  apt-get upgrade
################################################################
'

 rm -rf $SRC/*.x.c $SRC/*.x.sh *.spec
# rm -rf /tmp/*


#ufw allow 8000

#python_pros=$(pgrep -f python3)
#kill -9 $python_pros

#cd $repo_path && python3 -m http.server $PORT 
 rm -f apt.log

#cd $repo_path && python3 -m http.server $PORT &> repo.log &

# echo 'deb [arch=all signed-by=$repo_path/pgp-key.public] http://127.0.0.1:$PORT/apt-repo stable main' |  tee /etc/apt/sources.list.d/vova_repo.list

# echo 'deb [arch=all] http://127.0.0.1:$PORT/apt-repo stable main' |  tee /etc/apt/sources.list.d/vova_repo.list

#  apt-get update --allow-insecure-repositories
#  apt-get install b64
#  apt-get remove b64
