# NixOS Declarative eBPF Network Flow & DNS Profiler Configuration
{ config, pkgs, ... }:
{
  networking.hostName = "sentinel-worker-01";

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
