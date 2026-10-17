# Production unhardened NixOS WireGuard configuration fixture with scalar fallback & missing fastpath
{
  networking.wireguard.interfaces.wg0 = {
    mtu = 1500;
    fastpath.enable = false;
    cryptoVector = "GENERIC_SCALAR";
    ringBufferSize = 512;
    hardwareOffload = false;
    queueCount = 1;
  };
}
