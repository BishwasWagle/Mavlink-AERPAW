#!/usr/bin/env bash
set -euo pipefail

# OpenSSL FIPS build/install script (3.1.2)
# Installs to /usr/local/ssl
# Generates: /usr/local/ssl/fipsmodule.cnf and /usr/local/ssl/openssl.cnf
# Creates:   /etc/profile.d/openssl-fips.sh (env vars) and ./path.sh (local helper)

OPENSSL_VER="3.1.2"
SRC_DIR="/usr/local/src"
PREFIX="/usr/local/ssl"
OPENSSLDIR="/usr/local/ssl"
TARBALL="openssl-${OPENSSL_VER}.tar.gz"
URL="https://www.openssl.org/source/${TARBALL}"

# ---- helpers ----
die() { echo "ERROR: $*" >&2; exit 1; }
need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (use sudo)."; }

echo_step() { echo -e "\n========== $* ==========\n"; }

# ---- main ----
need_root

echo_step "Installing build dependencies"
apt update
apt install -y build-essential checkinstall git perl \
  libtool automake autoconf pkg-config wget ca-certificates

mkdir -p "${SRC_DIR}"
cd "${SRC_DIR}"

echo_step "Downloading OpenSSL ${OPENSSL_VER} source (if needed)"
if [[ ! -f "${TARBALL}" ]]; then
  wget -O "${TARBALL}" "${URL}"
else
  echo "Tarball already exists: ${SRC_DIR}/${TARBALL}"
fi

echo_step "Extracting source (if needed)"
if [[ ! -d "openssl-${OPENSSL_VER}" ]]; then
  tar -xf "${TARBALL}"
else
  echo "Source directory already exists: ${SRC_DIR}/openssl-${OPENSSL_VER}"
fi

cd "openssl-${OPENSSL_VER}"

echo_step "Configuring OpenSSL with FIPS (static build)"
./Configure enable-fips no-shared --prefix="${PREFIX}" --openssldir="${OPENSSLDIR}"

echo_step "Building"
make -j"$(nproc)"

echo_step "Installing to ${PREFIX}"
make install

# Detect lib directory (some systems use lib64)
LIBDIR="${PREFIX}/lib"
MODULEDIR="${LIBDIR}/ossl-modules"
if [[ -d "${PREFIX}/lib64" ]]; then
  # Prefer lib64 if it exists and contains ossl-modules
  if [[ -d "${PREFIX}/lib64/ossl-modules" ]]; then
    LIBDIR="${PREFIX}/lib64"
    MODULEDIR="${LIBDIR}/ossl-modules"
  fi
fi

[[ -d "${MODULEDIR}" ]] || die "Module directory not found: ${MODULEDIR}"
[[ -f "${MODULEDIR}/fips.so" ]] || die "FIPS module not found: ${MODULEDIR}/fips.so"

echo_step "Running fipsinstall (generates fipsmodule.cnf + runs self-tests)"
"${PREFIX}/bin/openssl" fipsinstall \
  -out "${PREFIX}/fipsmodule.cnf" \
  -module "${MODULEDIR}/fips.so"

echo_step "Writing OpenSSL config to enable FIPS provider (${PREFIX}/openssl.cnf)"
cat > "${PREFIX}/openssl.cnf" <<'EOF'
openssl_conf = openssl_init

.include /usr/local/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect

[provider_sect]
base = base_sect
fips = fips_sect

[base_sect]
activate = 1

[fips_sect]
activate = 1
EOF

echo_step "Creating env script (/etc/profile.d/openssl-fips.sh) and local helper (./path.sh)"
cat > /etc/profile.d/openssl-fips.sh <<EOF
# OpenSSL 3.1.2 FIPS environment
export PATH=${PREFIX}/bin:\$PATH
export LD_LIBRARY_PATH=${LIBDIR}:\$LD_LIBRARY_PATH
export OPENSSL_MODULES=${MODULEDIR}
export OPENSSL_CONF=${PREFIX}/openssl.cnf
EOF
chmod 0644 /etc/profile.d/openssl-fips.sh

cat > "${SRC_DIR}/path.sh" <<EOF
#!/usr/bin/env bash
export PATH=${PREFIX}/bin:\$PATH
export LD_LIBRARY_PATH=${LIBDIR}:\$LD_LIBRARY_PATH
export OPENSSL_MODULES=${MODULEDIR}
export OPENSSL_CONF=${PREFIX}/openssl.cnf
echo "Environment set:"
echo "  PATH=\$PATH"
echo "  LD_LIBRARY_PATH=\$LD_LIBRARY_PATH"
echo "  OPENSSL_MODULES=\$OPENSSL_MODULES"
echo "  OPENSSL_CONF=\$OPENSSL_CONF"
EOF
chmod +x "${SRC_DIR}/path.sh"

echo_step "Verification (should show OpenSSL 3.1.2 + FIPS provider active, MD5 blocked)"
# Use explicit binary to avoid system /usr/bin/openssl
"${PREFIX}/bin/openssl" version -a

# Load config/env for checks in current shell
export PATH="${PREFIX}/bin:${PATH}"
export LD_LIBRARY_PATH="${LIBDIR}:${LD_LIBRARY_PATH:-}"
export OPENSSL_MODULES="${MODULEDIR}"
export OPENSSL_CONF="${PREFIX}/openssl.cnf"

echo ""
echo "Providers:"
openssl list -providers

echo ""
echo "Test: MD5 should fail in FIPS-only provider set"
set +e
openssl md5 <<< "test" >/dev/null 2>&1
MD5_RC=$?
set -e
if [[ "${MD5_RC}" -eq 0 ]]; then
  echo "WARNING: MD5 succeeded. That usually means default provider is enabled somewhere."
  echo "Check OPENSSL_CONF=${OPENSSL_CONF} and providers output."
else
  echo "OK: MD5 blocked (expected in FIPS-only mode)."
fi

echo_step "Done"
echo "To use this OpenSSL in new shells: source /etc/profile.d/openssl-fips.sh (or log out/in)"
echo "For current session: source ${SRC_DIR}/path.sh"
