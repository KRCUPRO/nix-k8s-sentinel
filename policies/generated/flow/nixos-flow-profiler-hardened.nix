# NixOS Hardened eBPF Network Flow & DNS Exfiltration Profiler Module
# Generated autonomously by nix-k8s-sentinel
{
  services.cilium = {
    enable = true;
    debug = false;
  };

  programs.ebpf.flowProfiler = {
    enable = true;
    bpfConnectMonitoring = true;
    maxSocketRate = 250;
    dnsProxyPort = 10053;
    ringBufferSizeKB = 65536;
    dropThresholdPercent = 0.5;
  };

  boot.kernelParams = [
    "bpf_jit_enable=1"
    "bpf_jit_harden=2"
  ];
}
