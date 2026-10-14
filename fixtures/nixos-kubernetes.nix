# fixtures/nixos-kubernetes.nix
# Production-like NixOS Kubernetes module definition with mixed CIS compliance posture

{ config, pkgs, lib, ... }:

{
  services.kubernetes = {
    roles = [ "master" "node" ];

    # -------------------------------------------------------------
    # Control Plane: Kube-APIServer (CIS Section 1.2)
    # -------------------------------------------------------------
    apiserver = {
      enable = true;
      # VIOLATION: CIS-1.2.1: Anonymous auth should be disabled
      anonymousAuth = true;

      # VIOLATION: CIS-1.2.6: Authorization mode contains AlwaysAllow
      authorizationMode = [ "AlwaysAllow" "RBAC" ];

      # COMPLIANT: CIS-1.2.3: Kubelet HTTPS enabled
      kubeletHttps = true;

      # COMPLIANT: CIS-1.2.4 & CIS-1.2.5: Client cert and CA configured
      kubeletClientCertFile = "/var/lib/kubernetes/pki/apiserver-kubelet-client.crt";
      kubeletClientKeyFile = "/var/lib/kubernetes/pki/apiserver-kubelet-client.key";
      kubeletCaFile = "/var/lib/kubernetes/pki/ca.crt";

      # VIOLATION: CIS-1.2.14: Profiling should be false
      # VIOLATION: CIS-1.2.15: Missing audit log path
      extraOpts = "--profiling=true --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    };

    # -------------------------------------------------------------
    # Control Plane: Controller Manager (CIS Section 1.3)
    # -------------------------------------------------------------
    controllerManager = {
      enable = true;
      serviceAccountKeyFile = "/var/lib/kubernetes/pki/service-account.key";
      rootCaFile = "/var/lib/kubernetes/pki/ca.crt";

      # VIOLATION: CIS-1.3.7: Bind address exposed on all interfaces
      # VIOLATION: CIS-1.3.2: Profiling should be false
      extraOpts = "--bind-address=0.0.0.0 --profiling=true --use-service-account-credentials=true --terminated-pod-gc-threshold=12500";
    };

    # -------------------------------------------------------------
    # Control Plane: Scheduler (CIS Section 1.4)
    # -------------------------------------------------------------
    scheduler = {
      enable = true;
      # VIOLATION: CIS-1.4.2: Bind address exposed on 0.0.0.0
      extraOpts = "--bind-address=0.0.0.0 --profiling=false";
    };

    # -------------------------------------------------------------
    # Worker Node: Kubelet (CIS Section 4.2)
    # -------------------------------------------------------------
    kubelet = {
      enable = true;
      # VIOLATION: CIS-4.2.1: Anonymous auth enabled (CVE-2026-38102)
      # VIOLATION: CIS-4.2.4: Read-only port 10255 exposed
      # VIOLATION: CIS-4.2.2: Authorization mode set to AlwaysAllow
      # COMPLIANT: CIS-4.2.6: protect-kernel-defaults=true
      # COMPLIANT: CIS-4.2.10: rotate-certificates=true
      extraOpts = "--anonymous-auth=true --read-only-port=10255 --authorization-mode=AlwaysAllow --protect-kernel-defaults=true --rotate-certificates=true --client-ca-file=/var/lib/kubernetes/pki/ca.crt";
    };
  };

  # ---------------------------------------------------------------
  # Storage Backend: etcd (CIS Section 2)
  # ---------------------------------------------------------------
  services.etcd = {
    enable = true;
    certFile = "/var/lib/etcd/pki/etcd.crt";
    keyFile = "/var/lib/etcd/pki/etcd.key";
    peerCertFile = "/var/lib/etcd/pki/etcd-peer.crt";
    # VIOLATION: CIS-2.2: Client cert auth disabled
    clientCertAuth = false;
  };
}
