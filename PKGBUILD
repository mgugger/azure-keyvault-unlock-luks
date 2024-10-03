pkgname=azure-keyvault-unlock-luks
pkgver=0.0.1
pkgrel=1
pkgdesc="A tool to unlock LUKS volumes using Azure Key Vault"
arch=('x86_64')
url="https://github.com/mgugger/azure-keyvault-unlock-luks"
license=('MIT')
depends=('openssl' 'curl')
source=(
    "$pkgname-$pkgver.zip::https://github.com/mgugger/$pkgname/releases/download/v$pkgver/azure-keyvault-unlock-luks_x86_64.zip"
)
sha256sums=('1df2a2a77d2a5932f53073664c2177e9476da2eca5c876727623bc3bc5bacb32')

package() {
    install -Dm755 "$srcdir/luks_unlocker" "$pkgdir/usr/local/bin/luks_unlocker"
    install -Dm644 "$srcdir/etc/initcpio/hooks/luks_unlocker" "$pkgdir/etc/initcpio/hooks/luks_unlocker"
    install -Dm644 "$srcdir/etc/initcpio/install/luks_unlocker" "$pkgdir/etc/initcpio/install/luks_unlocker"
}