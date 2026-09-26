# STRIDE threat model

Spoofing is mitigated by SVID identity and cert-bound leases; tampering by AES-GCM and signed audit chains; repudiation by signatures; disclosure by taint scanning of modelled encodings; denial of service by bounded fail-closed code; privilege escalation by deny-by-default policies. Out of scope: paraphrase, steganography, screenshots, and timing channels.
